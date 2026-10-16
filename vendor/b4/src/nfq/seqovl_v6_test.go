package nfq

import (
	"encoding/binary"
	"testing"
)

func makeV6TCPPacket(payload []byte, seq uint32) []byte {
	const ipHL = 40
	const tcpHL = 20
	pkt := make([]byte, ipHL+tcpHL+len(payload))

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpHL+len(payload)))
	pkt[6] = 6
	pkt[7] = 64
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

	binary.BigEndian.PutUint16(pkt[ipHL:ipHL+2], 12345)
	binary.BigEndian.PutUint16(pkt[ipHL+2:ipHL+4], 443)
	binary.BigEndian.PutUint32(pkt[ipHL+4:ipHL+8], seq)
	pkt[ipHL+12] = byte(tcpHL/4) << 4
	pkt[ipHL+13] = 0x18

	copy(pkt[ipHL+tcpHL:], payload)
	return pkt
}

func TestBuildSeqOverlapSegmentV6_PrependsPatternAndShiftsSeq(t *testing.T) {
	origPayload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	startOff := 100
	pattern := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	seqovlLen := 7
	const baseSeq = uint32(1000)

	pkt := makeV6TCPPacket(origPayload, baseSeq)
	pi, ok := ExtractPacketInfoV6(pkt)
	if !ok {
		t.Fatal("ExtractPacketInfoV6 failed")
	}

	out := BuildSeqOverlapSegmentV6(pkt, pi, origPayload, startOff, seqovlLen, pattern)

	wantLen := pi.PayloadStart + seqovlLen + len(origPayload)
	if len(out) != wantLen {
		t.Fatalf("segment length: want %d, got %d", wantLen, len(out))
	}

	gotPayloadLen := binary.BigEndian.Uint16(out[4:6])
	wantPayloadLen := uint16(wantLen - 40)
	if gotPayloadLen != wantPayloadLen {
		t.Fatalf("IPv6 payload length: want %d, got %d", wantPayloadLen, gotPayloadLen)
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

func TestBuildSeqOverlapSegmentV6_ZeroLengthFallsBackToPlainSegment(t *testing.T) {
	origPayload := []byte{0xAA, 0xBB, 0xCC}
	pkt := makeV6TCPPacket(origPayload, 1000)
	pi, _ := ExtractPacketInfoV6(pkt)

	out := BuildSeqOverlapSegmentV6(pkt, pi, origPayload, 0, 0, []byte{0xFF})

	if len(out) != pi.PayloadStart+len(origPayload) {
		t.Fatalf("zero-length seqovl should not extend payload (got %d, want %d)",
			len(out), pi.PayloadStart+len(origPayload))
	}
	gotSeq := binary.BigEndian.Uint32(out[pi.IPHdrLen+4 : pi.IPHdrLen+8])
	if gotSeq != pi.Seq0 {
		t.Fatalf("zero-length seqovl should not shift seq (got %d, want %d)", gotSeq, pi.Seq0)
	}
}

func TestBuildSeqOverlapSegmentV6_EmptyPatternFallsBackToPlainSegment(t *testing.T) {
	origPayload := []byte{0xAA, 0xBB, 0xCC}
	pkt := makeV6TCPPacket(origPayload, 1000)
	pi, _ := ExtractPacketInfoV6(pkt)

	out := BuildSeqOverlapSegmentV6(pkt, pi, origPayload, 0, 5, nil)

	if len(out) != pi.PayloadStart+len(origPayload) {
		t.Fatalf("empty pattern should not extend payload (got %d, want %d)",
			len(out), pi.PayloadStart+len(origPayload))
	}
}
