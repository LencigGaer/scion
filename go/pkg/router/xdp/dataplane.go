package xdp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/scionproto/scion/go/lib/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-target bpf -O2 -g -DXDP_DEBUG_PRINT -DENABLE_IPV4 -DENABLE_IPV6 -DENABLE_SCION_PATH -DENABLE_HF_CHECK" br bpf/router.c -- -I./bpf

// A physical port of the border router with an underlying interface and its XDP hook.
type Port struct {
	netIf net.Interface
	link  *link.Link
}

// An internal interface is an interface to an AS-internal network.
type InternalIface struct {
	ifindex int
	local   net.UDPAddr
}

// An external interface is a local link to another AS.
type ExternalIface struct {
	ifid    uint16
	ifindex int
	local   net.UDPAddr
	remote  net.UDPAddr
}

// A sibling interface is a link to another AS via another BR in the same AS.
type SiblingIface struct {
	ifid    uint16
	sibling net.UDPAddr
}

// XDP in-kernel fast-path border router.
type Dataplane struct {
	bpfObjs     brObjects
	ports       map[int]Port
	internalIfs []InternalIface
	externalIfs []ExternalIface
	siblingIfs  []SiblingIface
}

func interfaceByIp(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			switch a := addr.(type) {
			case *net.IPNet:
				if a.IP.Equal(ip) {
					return &iface, nil
				}
			default:
				continue
			}
		}
	}
	return nil, fmt.Errorf("no interface with IP %v found", ip)
}

func (d *Dataplane) addXdpInterfaceByIp(ip net.IP) (int, error) {
	iface, err := interfaceByIp(ip)
	if err != nil {
		return 0, err
	}
	_, present := d.ports[iface.Index]
	if !present {
		log.Debug("Add interface for XDP attachment", "interface", iface)
		if d.ports == nil {
			d.ports = make(map[int]Port)
		}
		d.ports[iface.Index] = Port{
			netIf: *iface,
			link:  nil,
		}
	}
	return iface.Index, nil
}

// Add an internal interface.
func (d *Dataplane) AddInternalInterface(local net.UDPAddr) error {
	ifindex, err := d.addXdpInterfaceByIp(local.IP)
	if err != nil {
		return err
	}
	d.internalIfs = append(d.internalIfs, InternalIface{
		ifindex: ifindex,
		local:   local,
	})
	return nil
}

// Add an external interface belonging to this BR.
func (d *Dataplane) AddExternalInterface(ifid uint16, local net.UDPAddr, remote net.UDPAddr) error {
	ifindex, err := d.addXdpInterfaceByIp(local.IP)
	if err != nil {
		return err
	}
	d.externalIfs = append(d.externalIfs, ExternalIface{
		ifid:    ifid,
		ifindex: ifindex,
		local:   local,
		remote:  remote,
	})
	return nil
}

// Add an external interface belonging to a sibling BR.
func (d *Dataplane) AddSiblingInterface(ifid uint16, owner net.UDPAddr) error {
	d.siblingIfs = append(d.siblingIfs, SiblingIface{
		ifid:    ifid,
		sibling: owner,
	})
	return nil
}

func (d *Dataplane) Run(ctx context.Context) error {
	// Load BPF programs and maps
	err := loadBrObjects(&d.bpfObjs, nil)
	if err != nil {
		log.Error("Failed to load BPF objects", "err", err)
		return err
	}

	// Write to BPF maps
	for _, external := range d.externalIfs {
		key := make([]byte, 24)
		v4 := external.local.IP.To4()
		if v4 != nil {
			copy(key[0:3], v4)
		} else {
			copy(key[4:20], external.local.IP)
		}
		binary.LittleEndian.PutUint16(key[20:22], uint16(external.local.Port))
		binary.LittleEndian.PutUint16(key[22:24], uint16(external.ifindex))
		d.bpfObjs.IngressMap.Update(key, (uint32)(external.ifid), 0)
	}

	// Attach to interfaces
	for index, port := range d.ports {
		lnk, err := link.AttachXDP(link.XDPOptions{
			Program:   d.bpfObjs.BorderRouter,
			Interface: index,
		})
		if err != nil {
			log.Error("Attaching to XDP hook failed", "err", err)
			continue
		}
		port.link = &lnk
	}

	return nil
}
