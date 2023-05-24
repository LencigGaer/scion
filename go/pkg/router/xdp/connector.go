package xdp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"

	"github.com/asavie/xdp"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/pkg/router"
	"github.com/scionproto/scion/go/pkg/router/control"
)

type Connector struct {
	fast               Dataplane        // fast-path
	Slow               router.DataPlane // slow-path
	mtx                sync.Mutex
	ia                 addr.IA
	internalInterfaces []control.InternalInterface
	externalInterfaces map[uint16]control.ExternalInterface
	siblingInterfaces  map[uint16]control.SiblingInterface
}

const receiveBufferSize = 1 << 20

type XskObject struct {
	xsk       *xdp.Socket
	program   *xdp.Program
	link      netlink.Link
	local     net.Addr
	batchConn conn.Conn
}

var errMultiIA = serrors.New("different IA not allowed")

// Create XSK socket for reading and batch connection for sending
func (c *Connector) CreateXskConn(local net.UDPAddr) (*XskObject, error) {
	// Create XskObject
	x := new(XskObject)
	x.local = &local

	// Get interface name from IP
	iface, err := interfaceByIp(local.IP)
	if err != nil {
		return x, err
	}

	// Get link to which the XDP program should be attached
	x.link, err = netlink.LinkByName(iface.Name)
	if err != nil {
		return x, err
	}

	// Create socket
	x.xsk, err = xdp.NewSocket(x.link.Attrs().Index, 0, nil)
	if err != nil {
		log.Error("Failed to create XDP socket", "err", err)
		return x, err
	}
	c.fast.RegisterXdpSocket(x.link.Attrs().Index, 0, x.xsk.FD())

	// Create normal batch connection for sending
	x.batchConn, err = conn.New(&local, nil,
		&conn.Config{ReceiveBufferSize: receiveBufferSize})
	if err != nil {
		return x, err
	}
	return x, nil
}

// Read batch from XDP socket
func (x *XskObject) ReadBatch(msg conn.Messages) (int, error) {
	if n := x.xsk.NumFreeFillSlots(); n > 0 {
		x.xsk.Fill(x.xsk.GetDescs(len(msg)))
	}
	numRx, _, err := x.xsk.Poll(-1)
	if err != nil {
		log.Info("XDP socket poll failed", "err", err)
		return 0, err
	}
	if numRx > 0 {
		var rxDesc []xdp.Desc
		if numRx >= len(msg) {
			rxDesc = x.xsk.Receive(len(msg))
		} else {
			rxDesc = x.xsk.Receive(numRx)
		}
		for i := 0; i < len(rxDesc); i++ {
			raw_pkt := x.xsk.GetFrame(rxDesc[i])
			log.Debug(fmt.Sprint("Slow path got packet:\n", hex.Dump(raw_pkt)))
			msg[i].Buffers[0] = raw_pkt
			msg[i].Addr = x.local
			msg[i].N = 0
			msg[i].NN = 0
		}
		return len(rxDesc), nil
	}
	return 0, nil
}

// Write bytes to interface
func (x *XskObject) WriteTo(raw_pkt []byte, address *net.UDPAddr) (int, error) {
	return x.batchConn.WriteTo(raw_pkt, address)
}

// Write batch to interface
func (x *XskObject) WriteBatch(msgs conn.Messages, flags int) (int, error) {
	return x.batchConn.WriteBatch(msgs, flags)
}

// Detach XDP prog and close connection
func (x *XskObject) Close() error {
	x.xsk.Close()
	return x.batchConn.Close()
}

func (c *Connector) CreateIACtx(ia addr.IA) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("CreateIACtx", "isd_as", ia)
	if !c.ia.IsZero() {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.ia = ia
	c.fast.SetIA(ia)
	c.Slow.SetIA(ia)
	return nil
}

func (c *Connector) AddInternalInterface(ia addr.IA, local net.UDPAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding internal interface", "isd_as", ia, "local", local)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.internalInterfaces = append(c.internalInterfaces, control.InternalInterface{
		IA:   ia,
		Addr: &local,
	})
	if err := c.fast.AddInternalInterface(local); err != nil {
		return err
	}
	xskConn, err := c.CreateXskConn(local)
	if err != nil {
		return err
	}
	if err := c.Slow.AddInternalInterface(xskConn, local.IP); err != nil {
		return err
	}
	return nil
}

func (c *Connector) AddExternalInterface(
	localIfID common.IFIDType, link control.LinkInfo, owned bool) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	ifid := uint16(localIfID)
	log.Debug("Adding external interface", "interface", localIfID,
		"local_isd_as", link.Local.IA, "local_addr", link.Local.Addr,
		"remote_isd_as", link.Remote.IA, "remote_addr", link.Remote.IA,
		"owned", owned, "bfd", !link.BFD.Disable)

	if !c.ia.Equal(link.Local.IA) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", link.Local.IA)
	}
	if err := c.Slow.AddLinkType(ifid, link.LinkTo); err != nil {
		return serrors.WrapStr("adding link type", err, "if_id", localIfID)
	}
	if err := c.Slow.AddNeighborIA(ifid, link.Remote.IA); err != nil {
		return serrors.WrapStr("adding neighboring IA", err, "if_id", localIfID)
	}

	if owned {
		if len(c.externalInterfaces) == 0 {
			c.externalInterfaces = make(map[uint16]control.ExternalInterface)
		}
		c.externalInterfaces[ifid] = control.ExternalInterface{
			InterfaceID: ifid,
			Link:        link,
			State:       control.InterfaceDown,
		}
		err := c.fast.AddExternalInterface(ifid, *link.Local.Addr, *link.Remote.Addr)
		if err != nil {
			return err
		}
		xskConn, err := c.CreateXskConn(*link.Local.Addr)
		if err != nil {
			return err
		}
		if !link.BFD.Disable {
			err := c.Slow.AddExternalInterfaceBFD(ifid, xskConn, link.Local,
				link.Remote, link.BFD)
			if err != nil {
				return serrors.WrapStr("adding external BFD", err, "if_id", localIfID)
			}
		}
		err = c.Slow.AddExternalInterface(ifid, xskConn)
		if err != nil {
			return err
		}
	} else {
		if len(c.siblingInterfaces) == 0 {
			c.siblingInterfaces = make(map[uint16]control.SiblingInterface)
		}
		c.siblingInterfaces[ifid] = control.SiblingInterface{
			InterfaceID:       ifid,
			InternalInterface: link.Remote.Addr,
			Relationship:      link.LinkTo,
			MTU:               link.MTU,
			NeighborIA:        link.Remote.IA,
			State:             control.InterfaceDown,
		}
		if err := c.fast.AddSiblingInterface(ifid, *link.Remote.Addr); err != nil {
			return err
		}
		if !link.BFD.Disable {
			err := c.Slow.AddNextHopBFD(ifid, link.Local.Addr, link.Remote.Addr,
				link.BFD, link.Instance)
			if err != nil {
				return serrors.WrapStr("adding next hop BFD", err, "if_id", localIfID)
			}
		}
		err := c.Slow.AddNextHop(ifid, link.Remote.Addr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Connector) AddSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding service", "isd_as", ia, "svc", svc, "ip", ip)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.Slow.AddSvc(svc, &net.UDPAddr{IP: ip, Port: topology.EndhostPort})
	return nil
}

func (c *Connector) DelSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Deleting service", "isd_as", ia, "svc", svc, "ip", ip)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.Slow.DelSvc(svc, &net.UDPAddr{IP: ip, Port: topology.EndhostPort})
	return nil
}

func (c *Connector) SetKey(ia addr.IA, index int, key []byte) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Setting key", "isd_as", ia, "index", index)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	if index != 0 {
		return serrors.New("currently only index 0 key is supported")
	}
	c.Slow.SetKey(key)
	return nil
}

func (c *Connector) SetColibriKey(ia addr.IA, index int, key []byte) error {
	log.Debug("Setting Colibri key", "isd_as", ia, "index", index)
	if !c.ia.Equal(ia) {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	if index != 0 {
		return serrors.New("currently only index 0 key is supported")
	}
	c.Slow.SetColibriKey(key)
	return nil
}

func (c *Connector) ListInternalInterfaces() ([]control.InternalInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if len(c.internalInterfaces) == 0 {
		return nil, serrors.New("internal interface is not set")
	}
	return c.internalInterfaces, nil
}

func (c *Connector) ListExternalInterfaces() ([]control.ExternalInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	externalInterfaceList := make([]control.ExternalInterface, 0, len(c.externalInterfaces))
	for _, externalInterface := range c.externalInterfaces {
		externalInterface.State = c.Slow.GetInterfaceState(externalInterface.InterfaceID)
		externalInterfaceList = append(externalInterfaceList, externalInterface)
	}
	return externalInterfaceList, nil
}

func (c *Connector) ListSiblingInterfaces() ([]control.SiblingInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	siblingInterfaceList := make([]control.SiblingInterface, 0, len(c.siblingInterfaces))
	for _, siblingInterface := range c.siblingInterfaces {
		siblingInterface.State = c.Slow.GetInterfaceState(siblingInterface.InterfaceID)
		siblingInterfaceList = append(siblingInterfaceList, siblingInterface)
	}
	return siblingInterfaceList, nil
}

func (c *Connector) Run(ctx context.Context) error {
	// Create a socket for each network interface
	/*ifidxs := c.fast.GetIFindices()
	xsks := make(map[int]*xdp.Socket, len(ifidxs))
	for _, ifindex := range c.fast.GetIFindices() {
		xsk, err := xdp.NewSocket(ifidxs[ifindex], 0, nil)
		if err != nil {
			log.Error("Failed to create XDP socket", "err", err)
			continue
		}
		xsks[ifindex] = xsk
		c.fast.RegisterXdpSocket(ifidxs[ifindex], 0, xsk.FD())
		go func() {
			for {
				if n := xsk.NumFreeFillSlots(); n > 0 {
					xsk.Fill(xsk.GetDescs(n))
				}
				numRx, _, err := xsk.Poll(-1)
				if err != nil {
					log.Info("XDP socket poll failed", "err", err)
					return
				}
				if numRx > 0 {
					rxDescs := xsk.Receive(numRx)
					for i := 0; i < len(rxDescs); i++ {
						pkt := xsk.GetFrame(rxDescs[i])
						log.Debug(fmt.Sprint("Slow path got packet:\n", hex.Dump(pkt)))
					}
				}
			}
		}()
	}
	defer func() {
		for _, xsk := range xsks {
			xsk.Close()
		}
	}()*/

	// Run slow & fast path
	go func(ctx context.Context) {
		c.Slow.Run(ctx)
	}(ctx)
	return c.fast.Run(ctx)
}
