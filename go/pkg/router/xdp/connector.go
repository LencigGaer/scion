package xdp

import (
	"context"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/router/control"
)

type Connector struct {
	fast Dataplane // fast-path
	// TODO: Add slow-path
	mtx                sync.Mutex
	ia                 addr.IA
	internalInterfaces []control.InternalInterface
	externalInterfaces map[uint16]control.ExternalInterface
	siblingInterfaces  map[uint16]control.SiblingInterface
}

var errMultiIA = serrors.New("different IA not allowed")

func (c *Connector) CreateIACtx(ia addr.IA) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("CreateIACtx", "isd_as", ia)
	if !c.ia.IsZero() {
		return serrors.WithCtx(errMultiIA, "current", c.ia, "new", ia)
	}
	c.ia = ia
	c.fast.SetIA(ia)
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
	}

	return nil
}

func (c *Connector) AddSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding service", "isd_as", ia, "svc", svc, "ip", ip)
	return nil
}

func (c *Connector) DelSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Deleting service", "isd_as", ia, "svc", svc, "ip", ip)
	return nil
}

func (c *Connector) SetKey(ia addr.IA, index int, key []byte) error {
	log.Debug("Setting key", "isd_as", ia, "index", index)
	return nil
}

func (c *Connector) SetColibriKey(ia addr.IA, index int, key []byte) error {
	log.Debug("Setting Colibri key", "isd_as", ia, "index", index)
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
		// TODO: externalInterface.State = c.slow.getInterfaceState(externalInterface.InterfaceID)
		externalInterfaceList = append(externalInterfaceList, externalInterface)
	}
	return externalInterfaceList, nil
}

func (c *Connector) ListSiblingInterfaces() ([]control.SiblingInterface, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	siblingInterfaceList := make([]control.SiblingInterface, 0, len(c.siblingInterfaces))
	for _, siblingInterface := range c.siblingInterfaces {
		// TODO: siblingInterface.State = c.slow.getInterfaceState(siblingInterface.InterfaceID)
		siblingInterfaceList = append(siblingInterfaceList, siblingInterface)
	}
	return siblingInterfaceList, nil
}

func (c *Connector) Run(ctx context.Context) error {
	return c.fast.Run(ctx)
}
