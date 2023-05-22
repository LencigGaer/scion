package xdp

import (
	"context"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/pkg/router"
	"github.com/scionproto/scion/go/pkg/router/control"
)

// Currently, the slow path is simply a wrapper for the normal go border router

// receiveBufferSize is the size of receive buffers used by the router.
const receiveBufferSize = 1 << 20

type XdpObject struct {
	xsk       *xdp.Socket
	program   *xdp.Program
	link      netlink.Link
	local     net.Addr
	batchConn conn.Conn
}

type ConnectorSlowPath struct {
	DataPlane router.DataPlane

	ia                 addr.IA
	mtx                sync.Mutex
	internalInterfaces []control.InternalInterface
	externalInterfaces map[uint16]control.ExternalInterface
	siblingInterfaces  map[uint16]control.SiblingInterface
}

/*******************
 ** AF_XDP Helper **
 *******************/

// Create XDP socket
func (x *XdpObject) CreateXdp(local net.UDPAddr) error {
	// Save network address
	x.local = &local

	// Get interface name from IP
	iface, err := interfaceByIp(local.IP)
	if err != nil {
		return err
	}

	// Init queue ID
	queueId := 0

	// Get link to which the XDP program should be attached
	x.link, err = netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}

	// Create and attach XDP program
	x.program, err = xdp.NewProgram(queueId + 1)
	if err != nil {
		return err
	}
	if err := x.program.Attach(x.link.Attrs().Index); err != nil {
		return err
	}
	x.xsk, err = xdp.NewSocket(x.link.Attrs().Index, queueId, nil)
	if err != nil {
		return err
	}

	// Detach XDP in case of interrupt
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		x.program.Detach((x.link.Attrs().Index))
		os.Exit(1)
	}()

	// Create normal batch connection for sending
	x.batchConn, err = conn.New(&local, nil,
		&conn.Config{ReceiveBufferSize: receiveBufferSize})
	if err != nil {
		return err
	}
	return x.program.Register(queueId, x.xsk.FD())
}

// Read batch from XDP socket
func (x *XdpObject) ReadBatch(msg conn.Messages) (int, error) {
	x.xsk.Fill(x.xsk.GetDescs(len(msg)))
	numRx, _, err := x.xsk.Poll(-1)
	if err != nil {
		return 0, err
	}
	var rxDesc []xdp.Desc
	if numRx >= len(msg) {
		rxDesc = x.xsk.Receive(len(msg))
	} else {
		rxDesc = x.xsk.Receive(numRx)
	}
	for i := 0; i < len(rxDesc); i++ {
		raw_pkt := x.xsk.GetFrame(rxDesc[i])
		msg[i].Buffers[0] = raw_pkt
		msg[i].Addr = x.local
		msg[i].N = len(raw_pkt)
	}
	return len(rxDesc), nil
}

// Write bytes to interface
func (x *XdpObject) WriteTo(raw_pkt []byte, address *net.UDPAddr) (int, error) {
	return x.batchConn.WriteTo(raw_pkt, address)
}

// Write batch to interface
func (x *XdpObject) WriteBatch(msgs conn.Messages, flags int) (int, error) {
	return x.batchConn.WriteBatch(msgs, flags)
}

// Detach XDP prog and close connection
func (x *XdpObject) Close() error {
	x.program.Detach(x.link.Attrs().Index)
	return x.batchConn.Close()
}

/******************
 ** Dataplane IF **
 ******************/

// CreateIACtx creates the context for ISD-AS.
func (c *ConnectorSlowPath) CreateIACtx(ia addr.IA) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("CreateIACtx", "isd_as", ia)
	if !c.ia.IsZero() {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.ia = ia
	return c.DataPlane.SetIA(ia)
}

// AddInternalInterface adds the internal interface.
func (c *ConnectorSlowPath) AddInternalInterface(ia addr.IA, local net.UDPAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding internal interface", "isd_as", ia, "local", local)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	connection := new(XdpObject)
	err := connection.CreateXdp(local)
	if err != nil {
		return err
	}
	c.internalInterfaces = append(c.internalInterfaces, control.InternalInterface{
		IA:   ia,
		Addr: &local,
	})
	return c.DataPlane.AddInternalInterface(connection, local.IP)
}

// AddExternalInterface adds a link between the local and remote address.
func (c *ConnectorSlowPath) AddExternalInterface(localIfID common.IFIDType, link control.LinkInfo,
	owned bool) error {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	intf := uint16(localIfID)
	log.Debug("Adding external interface", "interface", localIfID,
		"local_isd_as", link.Local.IA, "local_addr", link.Local.Addr,
		"remote_isd_as", link.Remote.IA, "remote_addr", link.Remote.IA,
		"owned", owned, "bfd", !link.BFD.Disable)

	if !c.ia.Equal(link.Local.IA) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", link.Local.IA)
	}
	if err := c.DataPlane.AddLinkType(intf, link.LinkTo); err != nil {
		return serrors.WrapStr("adding link type", err, "if_id", localIfID)
	}
	if err := c.DataPlane.AddNeighborIA(intf, link.Remote.IA); err != nil {
		return serrors.WrapStr("adding neighboring IA", err, "if_id", localIfID)
	}

	if owned {
		if len(c.externalInterfaces) == 0 {
			c.externalInterfaces = make(map[uint16]control.ExternalInterface)
		}
		c.externalInterfaces[intf] = control.ExternalInterface{
			InterfaceID: intf,
			Link:        link,
			State:       control.InterfaceDown,
		}
	} else {
		if len(c.siblingInterfaces) == 0 {
			c.siblingInterfaces = make(map[uint16]control.SiblingInterface)
		}
		c.siblingInterfaces[intf] = control.SiblingInterface{
			InterfaceID:       intf,
			InternalInterface: link.Remote.Addr,
			Relationship:      link.LinkTo,
			MTU:               link.MTU,
			NeighborIA:        link.Remote.IA,
			State:             control.InterfaceDown,
		}
		if !link.BFD.Disable {
			err := c.DataPlane.AddNextHopBFD(intf, link.Local.Addr, link.Remote.Addr,
				link.BFD, link.Instance)
			if err != nil {
				return serrors.WrapStr("adding next hop BFD", err, "if_id", localIfID)
			}
		}
		return c.DataPlane.AddNextHop(intf, link.Remote.Addr)
	}

	connection := new(XdpObject)
	err := connection.CreateXdp(*link.Local.Addr)
	if err != nil {
		return err
	}
	if !link.BFD.Disable {
		err := c.DataPlane.AddExternalInterfaceBFD(intf, connection, link.Local,
			link.Remote, link.BFD)
		if err != nil {
			return serrors.WrapStr("adding external BFD", err, "if_id", localIfID)
		}
	}
	return c.DataPlane.AddExternalInterface(intf, connection)
}

// AddSvc adds the service address for the given ISD-AS.
func (c *ConnectorSlowPath) AddSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding service", "isd_as", ia, "svc", svc, "ip", ip)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	return c.DataPlane.AddSvc(svc, &net.UDPAddr{IP: ip, Port: topology.EndhostPort})
}

// DelSvc deletes the service entry for the given ISD-AS and IP pair.
func (c *ConnectorSlowPath) DelSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Deleting service", "isd_as", ia, "svc", svc, "ip", ip)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	return c.DataPlane.DelSvc(svc, &net.UDPAddr{IP: ip, Port: topology.EndhostPort})
}

// SetKey sets the key for the given ISD-AS at the given index.
func (c *ConnectorSlowPath) SetKey(ia addr.IA, index int, key []byte) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Setting key", "isd_as", ia, "index", index)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	if index != 0 {
		return serrors.New("currently only index 0 key is supported")
	}
	return c.DataPlane.SetKey(key)
}

// SetColibriKey sets the Colibri key for the given ISD-AS at the given index.
func (c *ConnectorSlowPath) SetColibriKey(ia addr.IA, index int, key []byte) error {
	log.Debug("Setting key", "isd_as", ia, "index", index)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	if index != 0 {
		return serrors.New("currently only index 0 key is supported")
	}
	return c.DataPlane.SetColibriKey(key)
}

func (c *ConnectorSlowPath) ListInternalInterfaces() ([]control.InternalInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if len(c.internalInterfaces) == 0 {
		return nil, serrors.New("internal interface is not set")
	}
	return c.internalInterfaces, nil
}

func (c *ConnectorSlowPath) ListExternalInterfaces() ([]control.ExternalInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	externalInterfaceList := make([]control.ExternalInterface, 0, len(c.externalInterfaces))
	for _, externalInterface := range c.externalInterfaces {
		externalInterface.State = c.DataPlane.GetInterfaceState(externalInterface.InterfaceID)
		externalInterfaceList = append(externalInterfaceList, externalInterface)
	}
	return externalInterfaceList, nil
}

func (c *ConnectorSlowPath) ListSiblingInterfaces() ([]control.SiblingInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	siblingInterfaceList := make([]control.SiblingInterface, 0, len(c.siblingInterfaces))
	for _, siblingInterface := range c.siblingInterfaces {
		siblingInterface.State = c.DataPlane.GetInterfaceState(siblingInterface.InterfaceID)
		siblingInterfaceList = append(siblingInterfaceList, siblingInterface)
	}
	return siblingInterfaceList, nil
}

func (c *ConnectorSlowPath) Run(ctx context.Context) error {
	return c.DataPlane.Run(ctx)
}
