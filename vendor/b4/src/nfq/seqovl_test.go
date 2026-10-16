package nfq

import (
	"encoding/binary"
	"testing"
)

func makeV4TCPPacket(payload []byte, seq uint32) []byte {
	const ipHL = 20
	const tcpHL = 20
	pkt := make([]byte, ipHL+tcpHL+len(payload))

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{1, 2, 3, 4})

	binary.BigEndian.PutUint16(pkt[ipHL:ipHL+2], 12345)
	binary.BigEndian.PutUint16(pkt[ipHL+2:ipHL+4], 443)
	binary.BigEndian.PutUint32(pkt[ipHL+4:ipHL+8], seq)
	pkt[ipHL+12] = byte(tcpHL/4) << 4
	pkt[ipHL+13] = 0x18

	copy(pkt[ipHL+tcpHL:], payload)
	return pkt
}

func TestBuildSeqOverlapSegmentV4_PrependsPatternAndShiftsSeq(t *testing.T) {
	origPayload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	startOff := 100
	pattern := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	seqovlLen := 7
	const baseSeq = uint32(1000)

	pkt := makeV4TCPPacket(origPayload, baseSeq)
	pi, ok := ExtractPacketInfoV4(pkt)
	if !ok {
		t.Fatal("ExtractPacketInfoV4 failed")
	}

	out := BuildSeqOverlapSegmentV4(pkt, pi, origPayload, startOff, seqovlLen, pattern, 0)

	wantLen := pi.PayloadStart + seqovlLen + len(origPayload)
	if len(out) != wantLen {
		t.Fatalf("segment length: want %d, got %d", wantLen, len(out))
	}

	gotIPLen := binary.BigEndian.Uint16(out[2:4])
	if int(gotIPLen) != wantLen {
		t.Fatalf("IP total length: want %d, got %d", wantLen, gotIPLen)
	}

	gotSeq := binary.BigEndian.Uint32(out[pi.IPHdrLen+4 : pi.IPHdrLen+8])
	wantSeq := pi.Seq0 + uint32(startOff) - uint32(seqovlLen)
	if gotSeq != wantSeq {
		t.Fatalf("seq: want %d, got %d", wantSeq, gotSeq)
	}

	body := out[pi.PayloadStart:]
	for i := 0; i < seqovlLen; i++ {
		if body[i] != pattern[i%len(pattern)] {
			t.Fatalf("prefix byte %d: want 0x%02X, got 0x%02X", i, pattern[i%len(pattern)], body[i])
		}
	}
	for i, b := range origPayload {
		if body[seqovlLen+i] != b {
			t.Fatalf("payload byte %d: want 0x%02X, got 0x%02X", i, b, body[seqovlLen+i])
		}
	}
}

func TestBuildSeqOverlapSegmentV4_ZeroLengthFallsBackToPlainSegment(t *testing.T) {
	origPayload := []byte{0xAA, 0xBB, 0xCC}
	pkt := makeV4TCPPacket(origPayload, 1000)
	pi, _ := ExtractPacketInfoV4(pkt)

	out := BuildSeqOverlapSegmentV4(pkt, pi, origPayload, 0, 0, []byte{0xFF}, 0)

	if len(out) != pi.PayloadStart+len(origPayload) {
		t.Fatalf("zero-length seqovl should not extend payload (got %d, want %d)",
			len(out), pi.PayloadStart+len(origPayload))
	}
	gotSeq := binary.BigEndian.Uint32(out[pi.IPHdrLen+4 : pi.IPHdrLen+8])
	if gotSeq != pi.Seq0 {
		t.Fatalf("zero-length seqovl should not shift seq (got %d, want %d)", gotSeq, pi.Seq0)
	}
}

func TestBuildSeqOverlapSegmentV4_EmptyPatternFallsBackToPlainSegment(t *testing.T) {
	origPayload := []byte{0xAA, 0xBB, 0xCC}
	pkt := makeV4TCPPacket(origPayload, 1000)
	pi, _ := ExtractPacketInfoV4(pkt)

	out := BuildSeqOverlapSegmentV4(pkt, pi, origPayload, 0, 5, nil, 0)

	if len(out) != pi.PayloadStart+len(origPayload) {
		t.Fatalf("empty pattern should not extend payload (got %d, want %d)",
			len(out), pi.PayloadStart+len(origPayload))
	}
}
