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
	fast Dataplane         // fast-path
	slow ConnectorSlowPath // slow-path
	mtx  sync.Mutex
	ia   addr.IA
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
	return c.slow.CreateIACtx(ia)
}

func (c *Connector) AddInternalInterface(ia addr.IA, local net.UDPAddr) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding internal interface", "isd_as", ia, "local", local)
	if err := c.fast.AddInternalInterface(local); err != nil {
		return err
	}
	return c.slow.AddInternalInterface(ia, local)
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
		err := c.fast.AddExternalInterface(ifid, *link.Local.Addr, *link.Remote.Addr)
		if err != nil {
			return err
		}
	} else {
		err := c.fast.AddSiblingInterface(ifid, *link.Remote.Addr)
		if err != nil {
			return err
		}
	}

	return c.slow.AddExternalInterface(localIfID, link, owned)
}

func (c *Connector) AddSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Adding service", "isd_as", ia, "svc", svc, "ip", ip)
	return c.slow.AddSvc(ia, svc, ip)
}

func (c *Connector) DelSvc(ia addr.IA, svc addr.HostSVC, ip net.IP) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	log.Debug("Deleting service", "isd_as", ia, "svc", svc, "ip", ip)
	return c.slow.DelSvc(ia, svc, ip)
}

func (c *Connector) SetKey(ia addr.IA, index int, key []byte) error {
	log.Debug("Setting key", "isd_as", ia, "index", index)
	return c.slow.SetKey(ia, index, key)
}

func (c *Connector) SetColibriKey(ia addr.IA, index int, key []byte) error {
	log.Debug("Setting Colibri key", "isd_as", ia, "index", index)
	return c.slow.SetColibriKey(ia, index, key)
}

func (c *Connector) ListInternalInterfaces() ([]control.InternalInterface, error) {
	return make([]control.InternalInterface, 0), nil
}

func (c *Connector) ListExternalInterfaces() ([]control.ExternalInterface, error) {
	return make([]control.ExternalInterface, 0), nil
}

func (c *Connector) ListSiblingInterfaces() ([]control.SiblingInterface, error) {
	return make([]control.SiblingInterface, 0), nil
}

func (c *Connector) Run(ctx context.Context) error {
	return c.fast.Run(ctx)
}
