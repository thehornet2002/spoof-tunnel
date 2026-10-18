//go:build windows

package transport

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	npcapInitOnce sync.Once
	npcapInitErr  error

	wpcap           *syscall.LazyDLL
	pcapOpenLive    *syscall.LazyProc
	pcapClose       *syscall.LazyProc
	pcapSendPacket  *syscall.LazyProc
	pcapNextEx      *syscall.LazyProc
	pcapCompile     *syscall.LazyProc
	pcapSetFilter   *syscall.LazyProc
	pcapFreeCode    *syscall.LazyProc
	pcapGetErr      *syscall.LazyProc
	pcapFindAllDevs *syscall.LazyProc
	pcapFreeAllDevs *syscall.LazyProc

	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP         = iphlpapi.NewProc("SendARP")
	procGetBestRoute    = iphlpapi.NewProc("GetBestRoute")
	procGetAdaptersInfo = iphlpapi.NewProc("GetAdaptersInfo")
)

type MIB_IPFORWARDROW struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

type IP_ADAPTER_INFO struct {
	Next                *IP_ADAPTER_INFO
	ComboIndex          uint32
	AdapterName         [260]byte
	Description         [132]byte
	AddressLength       uint32
	Address             [8]byte
	Index               uint32
	Type                uint32
	DhcpEnabled         uint32
	CurrentIpAddress    uintptr
	IpAddressList       [32]byte
	GatewayList         [32]byte
	DhcpServer          [32]byte
	HaveWins            int32
	PrimaryWinsServer   [32]byte
	SecondaryWinsServer [32]byte
	LeaseObtained       int64
	LeaseExpires        int64
}

type bpf_program struct {
	bf_len   uint32
	bf_insns uintptr
}

func ensureNpcapLoaded() error {
	npcapInitOnce.Do(func() {
		candidates := []string{
			`C:\Windows\System32\Npcap\wpcap.dll`,
			`wpcap.dll`,
		}
		for _, path := range candidates {
			dll := syscall.NewLazyDLL(path)
			if err := dll.Load(); err == nil {
				wpcap = dll
				pcapOpenLive = wpcap.NewProc("pcap_open_live")
				pcapClose = wpcap.NewProc("pcap_close")
				pcapSendPacket = wpcap.NewProc("pcap_sendpacket")
				pcapNextEx = wpcap.NewProc("pcap_next_ex")
				pcapCompile = wpcap.NewProc("pcap_compile")
				pcapSetFilter = wpcap.NewProc("pcap_setfilter")
				pcapFreeCode = wpcap.NewProc("pcap_freecode")
				pcapGetErr = wpcap.NewProc("pcap_geterr")
				pcapFindAllDevs = wpcap.NewProc("pcap_findalldevs")
				pcapFreeAllDevs = wpcap.NewProc("pcap_freealldevs")
				return
			}
		}
		npcapInitErr = fmt.Errorf("Npcap is not installed or wpcap.dll not found (download from https://npcap.com)")
	})
	return npcapInitErr
}

// resolveRouteAndDevice finds the local interface, local MAC, gateway MAC, and Npcap device name.
func resolveRouteAndDevice(dstIP net.IP, ifaceOverride string) (srcMAC [6]byte, dstMAC [6]byte, devName string, err error) {
	dst4 := dstIP.To4()
	if dst4 == nil {
		dst4 = net.IPv4(8, 8, 8, 8)
	}

	dstVal := binary.LittleEndian.Uint32(dst4)
	var row MIB_IPFORWARDROW
	r, _, _ := procGetBestRoute.Call(uintptr(dstVal), 0, uintptr(unsafe.Pointer(&row)))
	if r != 0 {
		return srcMAC, dstMAC, devName, fmt.Errorf("GetBestRoute failed: %d", r)
	}

	// Gateway IP in network byte order
	gwVal := row.ForwardNextHop
	if gwVal == 0 {
		gwVal = dstVal
	}

	// Resolve Gateway MAC via ARP
	macLen := uint32(6)
	rARP, _, _ := procSendARP.Call(uintptr(gwVal), 0, uintptr(unsafe.Pointer(&dstMAC[0])), uintptr(unsafe.Pointer(&macLen)))
	if rARP != 0 || macLen != 6 {
		// Fallback to broadcast MAC
		dstMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}

	// Find adapter info
	var bufSize uint32
	procGetAdaptersInfo.Call(0, uintptr(unsafe.Pointer(&bufSize)))
	if bufSize > 0 {
		buf := make([]byte, bufSize)
		rInfo, _, _ := procGetAdaptersInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufSize)))
		if rInfo == 0 {
			info := (*IP_ADAPTER_INFO)(unsafe.Pointer(&buf[0]))
			for info != nil {
				if info.Index == row.ForwardIfIndex {
					copy(srcMAC[:], info.Address[:6])
					nameBytes := make([]byte, 0, 260)
					for _, b := range info.AdapterName {
						if b == 0 {
							break
						}
						nameBytes = append(nameBytes, b)
					}
					devName = `\Device\NPF_` + string(nameBytes)
					break
				}
				info = info.Next
			}
		}
	}

	if ifaceOverride != "" {
		devName = ifaceOverride
	}

	if devName == "" {
		return srcMAC, dstMAC, devName, fmt.Errorf("failed to detect Npcap network device for index %d", row.ForwardIfIndex)
	}

	return srcMAC, dstMAC, devName, nil
}

// ═══════════════════════════════════════════════════════════
// NpcapSender
// ═══════════════════════════════════════════════════════════

type NpcapSender struct {
	transport string
	cfg       SenderConfig
	handle    uintptr
	srcMAC    [6]byte
	dstMAC    [6]byte
	ipIndex   atomic.Uint64
	seq       atomic.Uint32
	closed    atomic.Bool
	mu        sync.Mutex
}

func NewNpcapSender(transport string, cfg SenderConfig) (*NpcapSender, error) {
	if err := ensureNpcapLoaded(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// We resolve interface using first spoof IP or fallback
	ips := cfg.GetIPList()
	srcMAC, dstMAC, devName, err := resolveRouteAndDevice(ips[0], "")
	if err != nil {
		return nil, err
	}

	cDev := append([]byte(devName), 0)
	var errbuf [256]byte
	handle, _, _ := pcapOpenLive.Call(
		uintptr(unsafe.Pointer(&cDev[0])),
		65536,
		1,
		10,
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		return nil, fmt.Errorf("pcap_open_live on %s failed: %s", devName, string(errbuf[:]))
	}

	log.Printf("[npcap-sender] device=%s gateway_mac=%02X:%02X:%02X:%02X:%02X:%02X",
		devName, dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5])

	s := &NpcapSender{
		transport: transport,
		cfg:       cfg,
		handle:    handle,
		srcMAC:    srcMAC,
		dstMAC:    dstMAC,
	}
	s.seq.Store(rand.Uint32())
	return s, nil
}

func (s *NpcapSender) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if s.closed.Load() {
		return ErrConnectionClosed
	}

	dst4 := dstIP.To4()
	if dst4 == nil {
		return fmt.Errorf("IPv4 required")
	}

	ips := s.cfg.GetIPList()
	idx := s.ipIndex.Add(1)
	srcIP := ips[idx%uint64(len(ips))].To4()

	var proto uint8
	var l4HdrLen int

	switch s.transport {
	case TransportTCP:
		proto = 6
		l4HdrLen = 20
	case TransportUDP:
		proto = 17
		l4HdrLen = 8
	case TransportICMP:
		proto = 1
		l4HdrLen = 8
	default:
		return fmt.Errorf("unsupported transport: %s", s.transport)
	}

	totalLen := 14 + 20 + l4HdrLen + len(payload)
	frame := make([]byte, totalLen)

	// 1. Ethernet Header (14 bytes)
	copy(frame[0:6], s.dstMAC[:])
	copy(frame[6:12], s.srcMAC[:])
	frame[12] = 0x08
	frame[13] = 0x00

	// 2. IPv4 Header (20 bytes)
	ipHdr := frame[14 : 14+20]
	ipHdr[0] = 0x45
	ipHdr[1] = 0x00
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+l4HdrLen+len(payload)))
	binary.BigEndian.PutUint16(ipHdr[4:6], uint16(idx&0xffff))
	ipHdr[6] = 0x40
	ipHdr[7] = 0x00
	ipHdr[8] = 64
	ipHdr[9] = proto
	copy(ipHdr[12:16], srcIP)
	copy(ipHdr[16:20], dst4)
	binary.BigEndian.PutUint16(ipHdr[10:12], ipChecksum(ipHdr))

	// 3. Transport Header
	l4 := frame[34 : 34+l4HdrLen+len(payload)]
	switch s.transport {
	case TransportTCP:
		binary.BigEndian.PutUint16(l4[0:2], s.cfg.SourcePort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		seq := s.seq.Add(uint32(len(payload)))
		binary.BigEndian.PutUint32(l4[4:8], seq)
		binary.BigEndian.PutUint32(l4[8:12], 0)
		l4[12] = 0x50 // 20 bytes
		l4[13] = 0x02 // SYN
		binary.BigEndian.PutUint16(l4[14:16], 64240)
		copy(l4[20:], payload)
		csum := l4Checksum(srcIP, dst4, proto, l4)
		binary.BigEndian.PutUint16(l4[16:18], csum)

	case TransportUDP:
		binary.BigEndian.PutUint16(l4[0:2], s.cfg.SourcePort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
		copy(l4[8:], payload)
		csum := l4Checksum(srcIP, dst4, proto, l4)
		binary.BigEndian.PutUint16(l4[6:8], csum)

	case TransportICMP:
		l4[0] = 8 // Echo Request
		l4[1] = 0
		binary.BigEndian.PutUint16(l4[4:6], 0)
		binary.BigEndian.PutUint16(l4[6:8], uint16(idx&0xffff))
		copy(l4[8:], payload)
		binary.BigEndian.PutUint16(l4[2:4], ipChecksum(l4))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	res, _, _ := pcapSendPacket.Call(s.handle, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	if int32(res) != 0 {
		return fmt.Errorf("pcap_sendpacket failed")
	}
	return nil
}

func (s *NpcapSender) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != 0 {
		pcapClose.Call(s.handle)
		s.handle = 0
	}
	return nil
}

// ═══════════════════════════════════════════════════════════
// NpcapReceiver
// ═══════════════════════════════════════════════════════════

type NpcapReceiver struct {
	transport string
	cfg       ReceiverConfig
	handle    uintptr
	closed    atomic.Bool
	mu        sync.Mutex
}

func NewNpcapReceiver(transport string, cfg ReceiverConfig) (*NpcapReceiver, error) {
	if err := ensureNpcapLoaded(); err != nil {
		return nil, err
	}

	_, _, devName, err := resolveRouteAndDevice(nil, cfg.XDPInterface)
	if err != nil {
		return nil, err
	}

	cDev := append([]byte(devName), 0)
	var errbuf [256]byte
	handle, _, _ := pcapOpenLive.Call(
		uintptr(unsafe.Pointer(&cDev[0])),
		65536,
		1,
		50,
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		return nil, fmt.Errorf("pcap_open_live on %s failed: %s", devName, string(errbuf[:]))
	}

	// Optional BPF filter
	var filterStr string
	switch transport {
	case TransportTCP:
		if cfg.ListenPort > 0 {
			filterStr = fmt.Sprintf("tcp and dst port %d", cfg.ListenPort)
		} else {
			filterStr = "tcp"
		}
	case TransportUDP:
		if cfg.ListenPort > 0 {
			filterStr = fmt.Sprintf("udp and dst port %d", cfg.ListenPort)
		} else {
			filterStr = "udp"
		}
	case TransportICMP:
		filterStr = "icmp"
	}

	if filterStr != "" {
		var fcode bpf_program
		cFilter := append([]byte(filterStr), 0)
		rc, _, _ := pcapCompile.Call(
			handle,
			uintptr(unsafe.Pointer(&fcode)),
			uintptr(unsafe.Pointer(&cFilter[0])),
			1,
			0,
		)
		if int32(rc) == 0 {
			pcapSetFilter.Call(handle, uintptr(unsafe.Pointer(&fcode)))
			pcapFreeCode.Call(uintptr(unsafe.Pointer(&fcode)))
			log.Printf("[npcap-receiver] installed BPF filter: %q on %s", filterStr, devName)
		}
	}

	return &NpcapReceiver{
		transport: transport,
		cfg:       cfg,
		handle:    handle,
	}, nil
}

func (r *NpcapReceiver) Receive() (payload []byte, srcIP net.IP, srcPort uint16, err error) {
	for {
		if r.closed.Load() {
			return nil, nil, 0, ErrConnectionClosed
		}

		var hdrPtr uintptr
		var dataPtr uintptr

		r.mu.Lock()
		h := r.handle
		if h == 0 {
			r.mu.Unlock()
			return nil, nil, 0, ErrConnectionClosed
		}
		rc, _, _ := pcapNextEx.Call(h, uintptr(unsafe.Pointer(&hdrPtr)), uintptr(unsafe.Pointer(&dataPtr)))
		r.mu.Unlock()

		res := int32(rc)
		if res == 0 {
			// Timeout, loop
			time.Sleep(1 * time.Millisecond)
			continue
		}
		if res < 0 {
			if r.closed.Load() {
				return nil, nil, 0, ErrConnectionClosed
			}
			continue
		}

		// Frame received at dataPtr
		// Minimum Ethernet (14) + IP (20) = 34 bytes
		rawBytes := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), 65536)
		if len(rawBytes) < 34 {
			continue
		}

		// Check EtherType IPv4 (0x0800)
		if rawBytes[12] != 0x08 || rawBytes[13] != 0x00 {
			continue
		}

		ipHdr := rawBytes[14:]
		if ipHdr[0]>>4 != 4 {
			continue
		}
		ihl := int(ipHdr[0]&0x0F) * 4
		if len(ipHdr) < ihl {
			continue
		}

		totalLen := int(binary.BigEndian.Uint16(ipHdr[2:4]))
		if totalLen > len(ipHdr) {
			continue
		}

		pktSrcIP := net.IPv4(ipHdr[12], ipHdr[13], ipHdr[14], ipHdr[15])
		if r.cfg.PeerSpoofIP != nil && !pktSrcIP.Equal(r.cfg.PeerSpoofIP) {
			continue
		}

		proto := ipHdr[9]
		l4 := ipHdr[ihl:totalLen]

		switch r.transport {
		case TransportTCP:
			if proto != 6 || len(l4) < 20 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(l4[2:4])
			if r.cfg.ListenPort > 0 && dstPort != r.cfg.ListenPort {
				continue
			}
			dataOffset := int(l4[12]>>4) * 4
			if len(l4) < dataOffset {
				continue
			}
			sPort := binary.BigEndian.Uint16(l4[0:2])
			data := make([]byte, len(l4)-dataOffset)
			copy(data, l4[dataOffset:])
			return data, pktSrcIP, sPort, nil

		case TransportUDP:
			if proto != 17 || len(l4) < 8 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(l4[2:4])
			if r.cfg.ListenPort > 0 && dstPort != r.cfg.ListenPort {
				continue
			}
			sPort := binary.BigEndian.Uint16(l4[0:2])
			data := make([]byte, len(l4)-8)
			copy(data, l4[8:])
			return data, pktSrcIP, sPort, nil

		case TransportICMP:
			if proto != 1 || len(l4) < 8 {
				continue
			}
			data := make([]byte, len(l4)-8)
			copy(data, l4[8:])
			return data, pktSrcIP, 0, nil
		}
	}
}

func (r *NpcapReceiver) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle != 0 {
		pcapClose.Call(r.handle)
		r.handle = 0
	}
	return nil
}

// ═══════════════════════════════════════════════════════════
// Checksum Helpers
// ═══════════════════════════════════════════════════════════

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func l4Checksum(srcIP, dstIP net.IP, proto uint8, data []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2])) + uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2])) + uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(proto)
	sum += uint32(len(data))
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
