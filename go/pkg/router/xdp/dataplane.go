package xdp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"unsafe"

	"github.com/cilium/ebpf"
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
// #include "bpf/aes/aes.h"
// #include "bpf/common.h"
// #include <string.h>
// #cgo LDFLAGS: /home/robin/Programs/lars_scion/scion/go/pkg/router/xdp/aes.o
import "C"

//go:generate gcc bpf/aes/aes.c -I./bpf -c -o aes.o
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-target bpf -O2 -g -DXDP_DEBUG_PRINT -DENABLE_IPV4 -DENABLE_IPV6 -DENABLE_SCION_PATH -DENABLE_HF_CHECK" br bpf/router.c bpf/aes/aes.c -- -I./bpf

// Get a network interface by IP address.
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

// Packet/byte counters mirroring C.port_stats
// TODO: export prometheus metrics
type forwardingMetrics struct {
	Bytes   [C.COUNTER_ENUM_COUNT]uint64
	Packets [C.COUNTER_ENUM_COUNT]uint64
}

// A port of the border router with an underlying interface and its XDP hook.
type netInterface struct {
	netIf   net.Interface       // Underlying network interface
	link    link.Link           // Attached BPF program
	xsks    map[int]int         // XDP socket FD for each queue
	metrics []forwardingMetrics // Forwarding metrics from XDP per CPU
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

type brProgramsEx struct {
	BorderRouter map[int]*ebpf.Program
}

type brMapsEx struct {
	ROdata        *ebpf.Map
	AES_SBox      *ebpf.Map
	DebugRingbuf  *ebpf.Map
	EgressMap     *ebpf.Map
	IngressMap    *ebpf.Map
	IntIfaceMap   *ebpf.Map
	MacKeyMap     *ebpf.Map
	PortStatsMap  *ebpf.Map
	ScratchpadMap *ebpf.Map
	TxPortMap     *ebpf.Map
	XsksMaps      map[int]*ebpf.Map
}

type brObjsEx struct {
	brProgramsEx
	brMapsEx
}

func (o *brObjsEx) close() {
	var err error
	if err = o.ROdata.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.AES_SBox.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.DebugRingbuf.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.EgressMap.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.IngressMap.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.IntIfaceMap.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.MacKeyMap.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.PortStatsMap.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.ScratchpadMap.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	if err = o.TxPortMap.Close(); err != nil {
		log.Error("Closing bpf map FD failed", "err", err)
	}
	for ifindex, m := range o.XsksMaps {
		if err = m.Close(); err != nil {
			log.Error("Closing bpf map FD failed", "err", err)
		}
		delete(o.XsksMaps, ifindex)
	}
	for ifindex, prog := range o.BorderRouter {
		if err = prog.Close(); err != nil {
			log.Error("Closing bpf program FD failed", "err", err)
		}
		delete(o.BorderRouter, ifindex)
	}
}

// XDP in-kernel fast-path border router.
type Dataplane struct {
	localIA     addr.IA
	netIfs      map[int]netInterface
	internalIfs []InternalIface
	externalIfs []ExternalIface
	siblingIfs  []SiblingIface
	hfKeys      [8][16]byte
	running     bool
	bpfObjs     brObjsEx
}

// Return a slice of all network interface indices the XDP dataplane will attach to.
func (d *Dataplane) GetIFindices() []int {
	var ifidxs = make([]int, 0, len(d.netIfs))
	for ifindex := range d.netIfs {
		ifidxs = append(ifidxs, ifindex)
	}
	return ifidxs
}

// Set address of the local AS.
// Must be called before Run().
func (d *Dataplane) SetIA(ia addr.IA) {
	d.localIA = ia
}

// Add an internal interface.
// Must be called before Run().
func (d *Dataplane) AddInternalInterface(local net.UDPAddr) error {
	iface, err := d.addNetInterfaceByIp(local.IP)
	if err != nil {
		return err
	}
	d.internalIfs = append(d.internalIfs, InternalIface{
		ifindex: iface.netIf.Index,
		local:   local,
	})
	return nil
}

// Add an external interface belonging to this BR.
// Must be called before Run().
func (d *Dataplane) AddExternalInterface(ifid uint16, local net.UDPAddr, remote net.UDPAddr) error {
	iface, err := d.addNetInterfaceByIp(local.IP)
	if err != nil {
		return err
	}
	d.externalIfs = append(d.externalIfs, ExternalIface{
		ifid:    ifid,
		ifindex: iface.netIf.Index,
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

// Register an XDP socket for receiving packets that cannot be handled in eBPF.
// Must be called before Run().
func (d *Dataplane) RegisterXdpSocket(ifindex int, qid int, fd int) error {
	iface, err := d.addNetInterface(ifindex)
	if err != nil {
		return err
	}
	iface.xsks[qid] = fd
	if d.running {
		return d.bpfObjs.XsksMaps[ifindex].Put(qid, fd)
	}
	return nil
}

// Unregister an XDP socket from the given queue.
// Must be called before Run().
func (d *Dataplane) UnregisterXdpSocket(ifindex int, qid int) error {
	iface, ok := d.netIfs[ifindex]
	if ok {
		delete(iface.xsks, qid)
		if d.running {
			return d.bpfObjs.XsksMaps[ifindex].Delete(qid)
		}
	}
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

	// Load program and map specs from ELF file
	spec, err := loadBr()
	if err != nil {
		return serrors.WrapStr("failed to load BPF objects", err)
	}

	// Make sure all BPF objects will be closed
	defer d.bpfObjs.close()

	// Instantiate shared maps
	if d.bpfObjs.ROdata, err = ebpf.NewMap(spec.Maps[".rodata"]); err != nil {
		return err
	}
	if d.bpfObjs.AES_SBox, err = ebpf.NewMap(spec.Maps["AES_SBox"]); err != nil {
		return err
	}
	if d.bpfObjs.DebugRingbuf, err = ebpf.NewMap(spec.Maps["debug_ringbuf"]); err != nil {
		return err
	}
	if d.bpfObjs.EgressMap, err = ebpf.NewMap(spec.Maps["egress_map"]); err != nil {
		return err
	}
	if d.bpfObjs.IngressMap, err = ebpf.NewMap(spec.Maps["ingress_map"]); err != nil {
		return err
	}
	if d.bpfObjs.IntIfaceMap, err = ebpf.NewMap(spec.Maps["int_iface_map"]); err != nil {
		return err
	}
	if d.bpfObjs.MacKeyMap, err = ebpf.NewMap(spec.Maps["mac_key_map"]); err != nil {
		return err
	}
	if d.bpfObjs.PortStatsMap, err = ebpf.NewMap(spec.Maps["port_stats_map"]); err != nil {
		return err
	}
	if d.bpfObjs.ScratchpadMap, err = ebpf.NewMap(spec.Maps["scratchpad_map"]); err != nil {
		return err
	}
	if d.bpfObjs.TxPortMap, err = ebpf.NewMap(spec.Maps["tx_port_map"]); err != nil {
		return err
	}

	// Instantiate per-interface maps
	if d.bpfObjs.XsksMaps == nil {
		d.bpfObjs.XsksMaps = make(map[int]*ebpf.Map)
	}
	xsksMapSpec := spec.Maps["xsks_map"]
	for ifindex, iface := range d.netIfs {
		xsksMapSpec.Name = fmt.Sprintf("xsks_map_%d", ifindex)
		xsksMapSpec.Contents = make([]ebpf.MapKV, 0, len(iface.xsks))
		if iface.xsks != nil {
			for qid, fd := range iface.xsks {
				xsksMapSpec.Contents = append(xsksMapSpec.Contents,
					ebpf.MapKV{Key: (uint32)(qid), Value: (uint32)(fd)})
			}
		}
		m, err := ebpf.NewMap(xsksMapSpec)
		if err != nil {
			return err
		}
		d.bpfObjs.XsksMaps[ifindex] = m
	}

	// Instantiate a custom program for each interface
	if d.bpfObjs.BorderRouter == nil {
		d.bpfObjs.BorderRouter = make(map[int]*ebpf.Program)
	}
	for ifindex := range d.netIfs {
		brSpec := spec.Programs["border_router"].Copy()
		brSpec.Name = fmt.Sprintf("border_router_%d", ifindex)

		// Rewrite map references
		for i := range brSpec.Instructions {
			ins := &brSpec.Instructions[i]
			ref := ins.Reference()
			if !ins.IsLoadFromMap() || ref == "" {
				continue
			}
			switch ref {
			case ".rodata":
				ins.AssociateMap(d.bpfObjs.ROdata)
			case "AES_SBox":
				ins.AssociateMap(d.bpfObjs.AES_SBox)
			case "debug_ringbuf":
				ins.AssociateMap(d.bpfObjs.DebugRingbuf)
			case "egress_map":
				ins.AssociateMap(d.bpfObjs.EgressMap)
			case "ingress_map":
				ins.AssociateMap(d.bpfObjs.IngressMap)
			case "int_iface_map":
				ins.AssociateMap(d.bpfObjs.IntIfaceMap)
			case "mac_key_map":
				ins.AssociateMap(d.bpfObjs.MacKeyMap)
			case "port_stats_map":
				ins.AssociateMap(d.bpfObjs.PortStatsMap)
			case "scratchpad_map":
				ins.AssociateMap(d.bpfObjs.ScratchpadMap)
			case "tx_port_map":
				ins.AssociateMap(d.bpfObjs.TxPortMap)
			case "xsks_map":
				ins.AssociateMap(d.bpfObjs.XsksMaps[ifindex])
			default:
				return fmt.Errorf("unsatisfied reference in program %s to %s", brSpec.Name, ref)
			}
		}

		prog, err := ebpf.NewProgramWithOptions(brSpec, ebpf.ProgramOptions{
			LogLevel:    ebpf.LogLevelStats,
			LogSize:     ebpf.DefaultVerifierLogSize,
			LogDisabled: false,
		})
		if err != nil {
			return err
		}

		log.Debug(fmt.Sprint("BPF Verifier:\n", prog.VerifierLog))
		d.bpfObjs.BorderRouter[ifindex] = prog
	}

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
		if err = d.writeHfKey(i, key); err != nil {
			return serrors.WrapStr("writing to mac_key_map failed", err, "index", i)
		}
	}

	// Attach to interfaces
	for ifindex, iface := range d.netIfs {
		log.Debug(fmt.Sprintf("Attach BPF program to interface %d", ifindex))
		lnk, err := link.AttachXDP(link.XDPOptions{
			Program:   d.bpfObjs.BorderRouter[ifindex],
			Interface: ifindex,
		})
		if err != nil {
			log.Error("Attaching to XDP hook failed", "err", err)
			continue
		}
		iface.link = lnk
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
				null := bytes.Index(record.RawSample, []byte{0})
				msg := strings.TrimRight(string(record.RawSample[:null]), "\n")
				log.Debug(fmt.Sprintf("XDP: %s", msg))
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
	for ifindex, iface := range d.netIfs {
		log.Debug(fmt.Sprintf("Detach BPF program from interface %d", ifindex))
		if iface.link != nil {
			err := iface.link.Close()
			if err != nil {
				log.Error("Detaching XDP program failed", "err", err)
			}
			iface.link = nil
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

// Add a network interface to the border router.
// This is the only place where netInterface is instantiated.
func (d *Dataplane) addNetInterface(ifindex int) (*netInterface, error) {
	iface, present := d.netIfs[ifindex]
	if !present {
		log.Debug("Add interface for XDP attachment", "interface", iface)
		if d.netIfs == nil {
			d.netIfs = make(map[int]netInterface)
		}
		netIf, err := net.InterfaceByIndex(ifindex)
		if err != nil {
			return nil, serrors.WrapStr("interface not found", err)
		}
		d.netIfs[ifindex] = netInterface{
			netIf:   *netIf,
			xsks:    make(map[int]int),
			metrics: make([]forwardingMetrics, runtime.NumCPU()),
		}
		iface = d.netIfs[ifindex]
	}
	return &iface, nil
}

// Add a network interface by IP address.
func (d *Dataplane) addNetInterfaceByIp(ip net.IP) (*netInterface, error) {
	netIf, err := interfaceByIp(ip)
	if err != nil {
		return nil, err
	}
	return d.addNetInterface(netIf.Index)
}

// Write AES SBox for MAC calculation.
func (d *Dataplane) writeSBox() error {
	return d.bpfObjs.AES_SBox.Put((uint32)(0), C.AES_SBox)
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
		err := d.bpfObjs.IngressMap.Put(key, (uint32)(ext.ifid))
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
		err := d.bpfObjs.EgressMap.Put((uint32)(ext.ifid), value)
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
		err := d.bpfObjs.EgressMap.Put((uint32)(sib.ifid), value)
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
		err := d.bpfObjs.IntIfaceMap.Put((uint32)(intIf.ifindex), value)
		if err != nil {
			return err
		}
	}
	return nil
}

// Write one-to-one mapping of redirection port to interface for XDP_REDIRECT.
func (d *Dataplane) writeTxPortMap() error {
	for _, ext := range d.externalIfs {
		err := d.bpfObjs.TxPortMap.Put((uint32)(ext.ifindex), (uint32)(ext.ifindex))
		if err != nil {
			return err
		}
	}
	for _, intIf := range d.internalIfs {
		err := d.bpfObjs.TxPortMap.Put((uint32)(intIf.ifindex), (uint32)(intIf.ifindex))
		if err != nil {
			return err
		}
	}
	return nil
}

// Overwrite all known interface entries in the statistics map with zeros.
func (d *Dataplane) resetPortStatsMap() error {
	for ifindex := range d.netIfs {
		// FIXME: runtime.NumCPU() is the number of CPUs usable for Go at program startup,
		// not the number of CPUs currently online in the system
		value := make([]C.struct_port_stats, runtime.NumCPU())
		err := d.bpfObjs.PortStatsMap.Put((uint32)(ifindex), value)
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
	return d.bpfObjs.ScratchpadMap.Put((uint32)(0), value)
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
	return d.bpfObjs.MacKeyMap.Put((uint32)(index), hopKey)
}

// Read port metrics from XDP dataplane.
func (d *Dataplane) readPortStats() error {
	for ifindex, port := range d.netIfs {
		if err := d.bpfObjs.PortStatsMap.Lookup((uint32)(ifindex), &port.metrics); err != nil {
			return err
		}
	}
	return nil
}
