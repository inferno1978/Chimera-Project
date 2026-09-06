package sock

import (
	"encoding/binary"
	"testing"
)

func TestIPv4FragmentPacketTooShort(t *testing.T) {
	_, ok := IPv4FragmentPacket(make([]byte, 10), 10)
	if ok {
		t.Error("expected false for short packet")
	}
}

func TestIPv4FragmentPacketNotIPv4(t *testing.T) {
	pkt := buildMinimalIPv6TCPPacket(100)
	_, ok := IPv4FragmentPacket(pkt, 10)
	if ok {
		t.Error("expected false for IPv6 packet")
	}
}

func TestIPv4FragmentPacketValid(t *testing.T) {
	pkt := buildMinimalIPv4TCPPacket(100)
	frags, ok := IPv4FragmentPacket(pkt, 28)
	if !ok {
		t.Fatal("expected success")
	}
	if len(frags) != 2 {
		t.Errorf("expected 2 fragments, got %d", len(frags))
	}

	// First fragment should have MF flag set
	if frags[0][6]&0x20 == 0 {
		t.Error("expected More Fragments flag on first fragment")
	}

	// Second fragment should have non-zero fragment offset
	fragOff := binary.BigEndian.Uint16(frags[1][6:8]) & 0x1FFF
	if fragOff == 0 {
		t.Error("expected non-zero fragment offset on second fragment")
	}
}

func TestIPv4FragmentPacketSmallPayload(t *testing.T) {
	// Packet too small to fragment (less than IP header + 8 bytes)
	pkt := make([]byte, 24)
	pkt[0] = 0x45 // IPv4, IHL=5
	_, ok := IPv4FragmentPacket(pkt, 8)
	if ok {
		t.Error("expected false for packet with tiny IP payload")
	}
}

func TestIPv4FragmentPacketSplitAlignment(t *testing.T) {
	pkt := buildMinimalIPv4TCPPacket(100)
	// Pass unaligned split - should be aligned to 8 bytes internally
	frags, ok := IPv4FragmentPacket(pkt, 25)
	if !ok {
		t.Fatal("expected success")
	}

	// First fragment data length (after IP header) must be 8-byte aligned
	ipHdrLen := int((frags[0][0] & 0x0F) * 4)
	dataLen := len(frags[0]) - ipHdrLen
	if dataLen%8 != 0 {
		t.Errorf("fragment 1 data length %d is not 8-byte aligned", dataLen)
	}
}
