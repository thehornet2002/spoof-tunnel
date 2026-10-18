//go:build !windows

package tester

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
)

func (r *Runner) doSend(cfg TesterConfig, ranges *IPRangeSet, cancel <-chan struct{}) error {
	dstIP := net.ParseIP(cfg.DstIP).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid dst_ip: %s", cfg.DstIP)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw socket: %w (need root/CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP)

	total := ranges.Total()
	packetCount := cfg.PacketCount
	if packetCount < 1 {
		packetCount = 10
	}

	log.Printf("[tester-sender] protocol=%s dst=%s sources=%d packets_per_ip=%d",
		cfg.Protocol, dstIP, total, packetCount)

	var sent, errCount int
	var idx int
	ranges.IterateIPs(func(srcIP net.IP) bool {
		select {
		case <-cancel:
			return false
		default:
		}

		for p := 0; p < packetCount; p++ {
			var pkt []byte
			seq := uint16((idx*packetCount + p) % 65536)
			switch cfg.Protocol {
			case "tcp":
				pkt = BuildTCPSyn(srcIP, dstIP, cfg.DstPort)
			case "icmp":
				pkt = BuildICMPEcho(srcIP, dstIP, uint16(idx+1), seq)
			}

			if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
				errCount++
				continue
			}
			sent++
		}

		idx++
		r.mu.Lock()
		r.state.Progress = int(int64(idx) * 100 / total)
		r.mu.Unlock()
		return true
	})

	log.Printf("[tester-sender] done -- sent: %d, errors: %d", sent, errCount)
	return nil
}

func (r *Runner) doReceive(cfg TesterConfig, ranges *IPRangeSet, cancel <-chan struct{}) error {
	var proto int
	switch cfg.Protocol {
	case "tcp":
		proto = syscall.IPPROTO_TCP
	case "icmp":
		proto = syscall.IPPROTO_ICMP
	default:
		return fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return fmt.Errorf("raw socket: %w (need root/CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	timeout := cfg.Timeout
	if timeout < 1 {
		timeout = 30
	}
	packetCount := cfg.PacketCount
	if packetCount < 1 {
		packetCount = 10
	}
	maxLoss := cfg.MaxPacketLoss

	log.Printf("[tester-receiver] protocol=%s sources=%d packet_count=%d max_loss=%.1f%% timeout=%ds",
		cfg.Protocol, ranges.Total(), packetCount, maxLoss, timeout)

	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	startTime := time.Now()

	flushInterval := 5 * time.Minute
	lastFlush := time.Now()

	for time.Now().Before(deadline) {
		select {
		case <-cancel:
			goto buildResults
		default:
		}

		elapsed := time.Since(startTime)
		total := time.Duration(timeout) * time.Second
		r.mu.Lock()
		r.state.Progress = int(elapsed * 100 / total)
		r.mu.Unlock()

		if time.Since(lastFlush) >= flushInterval {
			r.flushInterimResults(packetCount, maxLoss)
			lastFlush = time.Now()
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		if n < 20 {
			continue
		}

		ihl := int(buf[0]&0x0f) * 4
		if n < ihl {
			continue
		}
		srcIPu32 := binary.BigEndian.Uint32(buf[12:16])

		if !ranges.Contains(srcIPu32) {
			continue
		}

		if cfg.DstPort > 0 && proto == syscall.IPPROTO_TCP {
			if n < ihl+4 {
				continue
			}
			dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
			if int(dstPort) != cfg.DstPort {
				continue
			}
		}

		r.recvMu.Lock()
		r.received[srcIPu32]++
		r.recvMu.Unlock()
	}

buildResults:
	r.flushInterimResults(packetCount, maxLoss)

	r.recvMu.RLock()
	recvTotal := len(r.received)
	r.recvMu.RUnlock()

	r.mu.Lock()
	passedCount := r.state.PassedCount
	r.mu.Unlock()

	log.Printf("[tester-receiver] done -- %d/%d IPs received packets, %d passed (loss <= %.1f%%)",
		recvTotal, ranges.Total(), passedCount, maxLoss)

	r.recvMu.Lock()
	r.received = nil
	r.recvMu.Unlock()

	return nil
}
