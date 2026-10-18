//go:build windows

package transport

import (
	"fmt"
)

// NewSender creates a Sender for the given transport type on Windows via Npcap.
func NewSender(transport string, cfg SenderConfig) (Sender, error) {
	switch transport {
	case TransportTCP, TransportUDP, TransportICMP:
		return NewNpcapSender(transport, cfg)
	default:
		return nil, fmt.Errorf("transport %q not supported on Windows (use tcp, udp, icmp)", transport)
	}
}

// NewReceiver creates a Receiver for the given transport type on Windows via Npcap.
func NewReceiver(transport string, cfg ReceiverConfig) (Receiver, error) {
	switch transport {
	case TransportTCP, TransportUDP, TransportICMP:
		return NewNpcapReceiver(transport, cfg)
	default:
		return nil, fmt.Errorf("transport %q not supported on Windows (use tcp, udp, icmp)", transport)
	}
}
