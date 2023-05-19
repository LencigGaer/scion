package xdp

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"runtime"
	"sync"
	"time"

	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
)

// #define ENABLE_IPV4
// #define ENABLE_IPV6
// #define ENABLE_SCION_PATH
// #define ENABLE_HF_CHECK
// #define AF_INET 2
// #define AF_INET6 10
// #include "bpf/common.h"
// #include <string.h>
import "C"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-target bpf -O2 -g -DXDP_DEBUG_PRINT -DENABLE_IPV4 -DENABLE_IPV6 -DENABLE_SCION_PATH -DENABLE_HF_CHECK" br bpf/router.c -- -I./bpf

type forwardingMetrics struct {
	ForwardedBytes   uint64
	ForwardedPackets uint64
}

// A physical port of the border router with an underlying interface and its XDP hook.
type Port struct {
	netIf   net.Interface
	link    link.Link
	metrics forwardingMetrics
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
	localIA     addr.IA
	ports       map[int]Port
	internalIfs []InternalIface
	externalIfs []ExternalIface
	siblingIfs  []SiblingIface
	hfKeys      [8][16]byte
	running     bool
	bpfObjs     brObjects
}

// Set address of the local AS.
// Must be called before Run().
func (d *Dataplane) SetIA(ia addr.IA) {
	d.localIA = ia
}

// Add an internal interface.
// Must be called before Run().
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
// Must be called before Run().
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
// Must be called before Run().
func (d *Dataplane) AddSiblingInterface(ifid uint16, owner net.UDPAddr) error {
	d.siblingIfs = append(d.siblingIfs, SiblingIface{
		ifid:    ifid,
		sibling: owner,
	})
	return nil
}

// Set hop field verification key.
// Keys can be updated while the dataplane is running.
func (d *Dataplane) SetKey(index int, key []byte) error {
	copy(d.hfKeys[index][:], key[:16])
	if d.running {
		return d.writeHfKey(index, d.hfKeys[index])
	}
	return nil
}

func (d *Dataplane) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	// Load BPF programs and maps
	err := loadBrObjects(&d.bpfObjs, nil)
	if err != nil {
		log.Error("Failed to load BPF objects", "err", err)
		return err
	}
	defer d.bpfObjs.Close()

	// Initialize BPF maps
	err = d.writeSBox()
	if err != nil {
		return serrors.WrapStr("writing to AES_SBox failed", err)
	}
	err = d.writeIngressMap()
	if err != nil {
		return serrors.WrapStr("writing to ingress_map failed", err)
	}
	err = d.writeEgressMap()
	if err != nil {
		return serrors.WrapStr("writing to egress_map failed", err)
	}
	err = d.writeIntIfMap()
	if err != nil {
		return serrors.WrapStr("writing to int_iface_map failed", err)
	}
	err = d.writeTxPortMap()
	if err != nil {
		return serrors.WrapStr("writing to tx_port_map failed", err)
	}
	err = d.resetPortStatsMap()
	if err != nil {
		return serrors.WrapStr("writing to port_stats_map failed", err)
	}
	err = d.initScratchpad()
	if err != nil {
		return serrors.WrapStr("writing to scratchpad_map failed", err)
	}
	for i, key := range d.hfKeys {
		err = d.writeHfKey(i, key)
		if err != nil {
			return serrors.WrapStr("writing to mac_key_map failed", err, "index", i)
		}
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
		port.link = lnk
	}

	// Launch goroutine for reading from debug ringbuf
	rd, err := ringbuf.NewReader(d.bpfObjs.DebugRingbuf)
	if err != nil {
		log.Error("Reading from debug ringbuffer failed", "err", err)
	} else {
		wg.Add(1)
		go func() {
			for {
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						wg.Done()
						return
					}
					log.Error("Reading from ringbuf reader failed", "err", err)
					continue
				}
				log.Debug(fmt.Sprint("XDP:", record.RawSample))
			}
		}()
	}

	// Keep metrics synchronized with XDP dataplane
	ticker := time.NewTicker(1 * time.Second)
	wg.Add(1)
	go func() {
		for range ticker.C {
			if err := d.readPortStats(); err != nil {
				log.Error("Reading port metrics from XDP failed", "err", err)
			}
		}
		wg.Done()
	}()

	// Wait until the BR is exiting
	<-ctx.Done()

	// Detach XDP
	for _, port := range d.ports {
		if port.link != nil {
			err := port.link.Close()
			if err != nil {
				log.Error("Detaching XDP program failed", "err", err)
			}
			port.link = nil
		}
	}

	// Signal goroutines to exit and wait for them before removing the BPF objects
	if rd != nil {
		rd.Close()
	}
	ticker.Stop()
	wg.Wait()

	return nil
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

// Write AES SBox for MAC calculation.
func (d *Dataplane) writeSBox() error {
	return d.bpfObjs.AES_SBox.Update(0, C.AES_SBox, 0)
}

// Write map for matching ingress packets against BR interfaces.
func (d *Dataplane) writeIngressMap() error {
	for _, ext := range d.externalIfs {
		key := C.struct_ingress_addr{
			port:    C.ushort(bits.ReverseBytes16((uint16)(ext.local.Port))),
			ifindex: C.ushort(ext.ifindex),
		}
		v4 := ext.local.IP.To4()
		if v4 != nil {
			C.memcpy(unsafe.Pointer(&key.ipv4), unsafe.Pointer(&v4[0]), 4)
		} else {
			C.memcpy(unsafe.Pointer(&key.ipv6), unsafe.Pointer(&ext.local.IP[0]), 16)
		}
		err := d.bpfObjs.IngressMap.Update(key, (uint32)(ext.ifid), 0)
		if err != nil {
			return err
		}
	}
	return nil
}

// Write address information for redirecting packets.
func (d *Dataplane) writeEgressMap() error {
	// Links to direct neighbor ASes
	for _, ext := range d.externalIfs {
		value := C.struct_fwd_info{
			fwd_external: C.uint(1),
		}
		link := (*C.struct_ext_link)(unsafe.Pointer(&value.anon0[0]))
		localv4 := ext.local.IP.To4()
		remotev4 := ext.remote.IP.To4()
		if localv4 != nil && remotev4 != nil {
			link.ip_family = C.AF_INET
			C.memcpy(unsafe.Pointer(&link.anon0[0]), unsafe.Pointer(&localv4[0]), 4)
			C.memcpy(unsafe.Pointer(&link.anon0[4]), unsafe.Pointer(&remotev4[0]), 4)
		} else if localv4 == nil && remotev4 == nil {
			link.ip_family = C.AF_INET6
			C.memcpy(unsafe.Pointer(&link.anon0[0]), unsafe.Pointer(&ext.local.IP[0]), 16)
			C.memcpy(unsafe.Pointer(&link.anon0[16]), unsafe.Pointer(&ext.remote.IP[0]), 16)
		} else {
			return fmt.Errorf("invalid underlay addresses (mixing IPv4 and IPv6)")
		}
		link.remote_port = C.ushort(bits.ReverseBytes16((uint16)(ext.remote.Port)))
		link.local_port = C.ushort(bits.ReverseBytes16((uint16)(ext.local.Port)))
		err := d.bpfObjs.EgressMap.Update((uint32)(ext.ifid), value, 0)
		if err != nil {
			return err
		}
	}

	// Links to neighbor ASes via sibling routers
	for _, sib := range d.siblingIfs {
		value := C.struct_fwd_info{
			fwd_external: C.uint(0),
		}
		sibling := (*C.struct_endpoint)(unsafe.Pointer(&value.anon0[0]))
		v4 := sib.sibling.IP.To4()
		if v4 != nil {
			sibling.ip_family = C.AF_INET
			C.memcpy(unsafe.Pointer(&sibling.anon0[0]), unsafe.Pointer(&v4[0]), 4)
		} else {
			sibling.ip_family = C.AF_INET6
			C.memcpy(unsafe.Pointer(&sibling.anon0[0]), unsafe.Pointer(&sib.sibling.IP[0]), 16)
		}
		sibling.port = C.ushort(bits.ReverseBytes16((uint16)(sib.sibling.Port)))
		err := d.bpfObjs.EgressMap.Update((uint32)(sib.ifid), value, 0)
		if err != nil {
			return err
		}
	}

	return nil
}

// Write information on AS internal interfaces.
func (d *Dataplane) writeIntIfMap() error {
	for _, intIf := range d.internalIfs {
		value := C.struct_endpoint{}
		v4 := intIf.local.IP.To4()
		if v4 != nil {
			value.ip_family = C.AF_INET
			C.memcpy(unsafe.Pointer(&value.anon0[0]), unsafe.Pointer(&v4[0]), 4)
		} else {
			value.ip_family = C.AF_INET6
			C.memcpy(unsafe.Pointer(&value.anon0[0]), unsafe.Pointer(&intIf.local.IP[0]), 16)
		}
		value.port = C.ushort(bits.ReverseBytes16((uint16)(intIf.local.Port)))
		err := d.bpfObjs.IntIfaceMap.Update((uint32)(intIf.ifindex), value, 0)
		if err != nil {
			return err
		}
	}
	return nil
}

// Write one-to-one mapping of redirection port to interface for XDP_REDIRECT.
func (d *Dataplane) writeTxPortMap() error {
	for _, ext := range d.externalIfs {
		err := d.bpfObjs.TxPortMap.Update(ext.ifindex, ext.ifindex, 0)
		if err != nil {
			return err
		}
	}
	for _, intIf := range d.internalIfs {
		err := d.bpfObjs.TxPortMap.Update(intIf.ifindex, intIf.ifindex, 0)
		if err != nil {
			return err
		}
	}
	return nil
}

// Overwrite all known interface entries in the statistics map with zeros.
func (d *Dataplane) resetPortStatsMap() error {
	for ifindex := range d.ports {
		// FIXME: runtime.NumCPU() is the number of CPUs usable for Go at program startup,
		// not the number of CPUs currently online in the system
		value := make([]C.struct_port_stats, runtime.NumCPU())
		err := d.bpfObjs.PortStatsMap.Update(ifindex, value, 0)
		if err != nil {
			return err
		}
	}
	return nil
}

// Initialize the scratchpad map (which exists to circumvent stack size restrictions in BPF).
func (d *Dataplane) initScratchpad() error {
	// FIXME: runtime.NumCPU() is the number of CPUs usable for Go at program startup,
	// not the number of CPUs currently online in the system
	var value = make([]C.struct_scratchpad, runtime.NumCPU())
	for _, scratchpad := range value {
		scratchpad.local_as = C.ulonglong(d.localIA)
		scratchpad.host_port = C.uint(topology.EndhostPort)
	}
	return d.bpfObjs.ScratchpadMap.Update(0, value, 0)
}

// Expand and write a hop field verification key to the slot given by index.
func (d *Dataplane) writeHfKey(index int, key [16]byte) error {
	var (
		aesKey  = C.struct_aes_key{}
		hopKey  = C.struct_hop_key{}
		subkeys = [2]C.struct_aes_block{}
	)
	copy(aesKey.anon0[:], key[:16])
	C.aes_key_expansion(&aesKey, &hopKey.key)
	C.aes_cmac_subkeys(&hopKey.key, &subkeys[0])
	copy(hopKey.subkey.anon0[:], subkeys[1].anon0[:16])
	return d.bpfObjs.MacKeyMap.Update(index, hopKey, 0)
}

// Read port metrics from XDP dataplane.
func (d *Dataplane) readPortStats() error {
	for ifindex, port := range d.ports {
		value := make([]C.struct_port_stats, runtime.NumCPU())
		if err := d.bpfObjs.PortStatsMap.Lookup(ifindex, value); err != nil {
			return err
		}
		port.metrics.ForwardedBytes = 0
		port.metrics.ForwardedPackets = 0
		for _, stats := range value {
			port.metrics.ForwardedBytes += (uint64)(stats.verdict_bytes[C.COUNTER_SCION_FORWARD])
			port.metrics.ForwardedPackets += (uint64)(stats.verdict_pkts[C.COUNTER_SCION_FORWARD])
		}
	}
	return nil
}
