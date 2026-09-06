package sock

import "testing"

func TestIPv6FragmentPacket_TooShort(t *testing.T) {
	_, ok := IPv6FragmentPacket(make([]byte, 30), 10)
	if ok {
		t.Error("expected false")
	}
}

func TestIPv6FragmentPacket_NotIPv6(t *testing.T) {
	pkt := buildMinimalIPv4TCPPacket(100)
	_, ok := IPv6FragmentPacket(pkt, 10)
	if ok {
		t.Error("expected false for IPv4")
	}
}

func TestIPv6FragmentPacket_Valid(t *testing.T) {
	pkt := buildMinimalIPv6TCPPacket(100)
	frags, ok := IPv6FragmentPacket(pkt, 16)
	if !ok {
		t.Fatal("expected success")
	}
	if len(frags) != 2 {
		t.Errorf("expected 2 fragments, got %d", len(frags))
	}

	// First fragment should have next header = 44 (Fragment)
	if frags[0][6] != 44 {
		t.Errorf("expected fragment header, got %d", frags[0][6])
	}
}
