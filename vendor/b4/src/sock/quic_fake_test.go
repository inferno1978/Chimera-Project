package sock

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildQUICInitial_TooShort(t *testing.T) {
	if got := BuildQUICInitial(29); got != nil {
		t.Errorf("expected nil for size < %d, got %d bytes", quicFakeHeaderLen, len(got))
	}
}

func TestBuildQUICInitial_MinSize(t *testing.T) {
	got := BuildQUICInitial(quicFakeHeaderLen)
	if got == nil {
		t.Fatalf("expected non-nil for size == %d", quicFakeHeaderLen)
	}
	if len(got) != quicFakeHeaderLen {
		t.Errorf("expected len %d, got %d", quicFakeHeaderLen, len(got))
	}
}

func TestBuildQUICInitial_StructuralConstants(t *testing.T) {
	pkt := BuildQUICInitial(1200)
	if pkt == nil {
		t.Fatal("expected non-nil")
	}
	if pkt[0] != 0xC3 {
		t.Errorf("byte 0: expected 0xC3, got 0x%02X", pkt[0])
	}
	if !bytes.Equal(pkt[1:5], []byte{0x00, 0x00, 0x00, 0x01}) {
		t.Errorf("version bytes: expected 00 00 00 01, got % X", pkt[1:5])
	}
	if pkt[5] != 0x08 {
		t.Errorf("DCID length: expected 0x08, got 0x%02X", pkt[5])
	}
	if pkt[14] != 0x08 {
		t.Errorf("SCID length: expected 0x08, got 0x%02X", pkt[14])
	}
	if pkt[23] != 0x00 {
		t.Errorf("token length: expected 0x00, got 0x%02X", pkt[23])
	}
	if !bytes.Equal(pkt[26:30], []byte{0x00, 0x00, 0x00, 0x00}) {
		t.Errorf("packet number: expected 00 00 00 00, got % X", pkt[26:30])
	}
}

func TestBuildQUICInitial_LengthVarint(t *testing.T) {
	cases := []struct {
		size            int
		expectedCovered uint16
	}{
		{30, 4},
		{100, 74},
		{1200, 1174},
		{quicFakeMaxSize, 0x3FFF},
	}
	for _, c := range cases {
		pkt := BuildQUICInitial(c.size)
		if pkt == nil {
			t.Fatalf("size=%d returned nil", c.size)
		}
		got := binary.BigEndian.Uint16(pkt[24:26])
		expected := uint16(0x4000) | c.expectedCovered
		if got != expected {
			t.Errorf("size=%d: expected length varint 0x%04X, got 0x%04X", c.size, expected, got)
		}
	}
}

func TestBuildQUICInitial_TooLarge(t *testing.T) {
	if got := BuildQUICInitial(quicFakeMaxSize + 1); got != nil {
		t.Errorf("expected nil for size > %d, got %d bytes", quicFakeMaxSize, len(got))
	}
}

func TestBuildQUICInitial_ConnectionIDsRandom(t *testing.T) {
	a := BuildQUICInitial(1200)
	b := BuildQUICInitial(1200)
	if a == nil || b == nil {
		t.Fatal("expected non-nil")
	}
	if bytes.Equal(a[6:14], b[6:14]) {
		t.Error("DCID identical across two calls (randomness broken)")
	}
	if bytes.Equal(a[15:23], b[15:23]) {
		t.Error("SCID identical across two calls (randomness broken)")
	}
}
