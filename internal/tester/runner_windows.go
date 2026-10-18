//go:build windows

package tester

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/internal/transport"
)

func (r *Runner) doSend(cfg TesterConfig, ranges *IPRangeSet, cancel <-chan struct{}) error {
	dstIP := net.ParseIP(cfg.DstIP).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid dst_ip: %s", cfg.DstIP)
	}

	total := ranges.Total()
	packetCount := cfg.PacketCount
	if packetCount < 1 {
		packetCount = 10
	}

	log.Printf("[tester-sender] protocol=%s dst=%s sources=%d packets_per_ip=%d (Npcap)",
		cfg.Protocol, dstIP, total, packetCount)

	var sent, errCount int
	var idx int

	ranges.IterateIPs(func(srcIP net.IP) bool {
		select {
		case <-cancel:
			return false
		default:
		}

		sender, err := transport.NewSender(cfg.Protocol, transport.SenderConfig{
			SourceIP:   srcIP,
			SourcePort: 1024 + uint16(idx%60000),
			MTU:        1400,
		})
		if err != nil {
			errCount++
			idx++
			return true
		}
		defer sender.Close()

		for p := 0; p < packetCount; p++ {
			var payload []byte
			switch cfg.Protocol {
			case "tcp":
				payload = []byte("SPOOF_TEST")
			case "icmp":
				payload = []byte("PING")
			}

			if err := sender.Send(payload, dstIP, uint16(cfg.DstPort)); err != nil {
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
	timeout := cfg.Timeout
	if timeout < 1 {
		timeout = 30
	}
	packetCount := cfg.PacketCount
	if packetCount < 1 {
		packetCount = 10
	}
	maxLoss := cfg.MaxPacketLoss

	recver, err := transport.NewReceiver(cfg.Protocol, transport.ReceiverConfig{
		ListenPort: uint16(cfg.DstPort),
	})
	if err != nil {
		return err
	}
	defer recver.Close()

	log.Printf("[tester-receiver] protocol=%s sources=%d packet_count=%d max_loss=%.1f%% timeout=%ds (Npcap)",
		cfg.Protocol, ranges.Total(), packetCount, maxLoss, timeout)

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	startTime := time.Now()

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

		_, srcIP, _, err := recver.Receive()
		if err != nil {
			continue
		}
		src4 := srcIP.To4()
		if src4 == nil {
			continue
		}
		srcIPu32 := binary.BigEndian.Uint32(src4)
		if !ranges.Contains(srcIPu32) {
			continue
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
