package sock

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildPacketWithSACK() []byte {
	ipHdrLen := 20
	// TCP header with options: MSS(4) + SACK-Permitted(2) + NOP(1) + NOP(1) + SACK(10) = 18, padded to 20
	tcpHdrLen := 40

	pkt := make([]byte, ipHdrLen+tcpHdrLen+10)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 168, 1, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 1})

	// TCP header
	binary.BigEndian.PutUint16(pkt[ipHdrLen:], 12345)
	binary.BigEndian.PutUint16(pkt[ipHdrLen+2:], 443)
	pkt[ipHdrLen+12] = byte((tcpHdrLen / 4) << 4)
	pkt[ipHdrLen+13] = 0x18

	// Options starting at offset 20 within TCP header
	opts := pkt[ipHdrLen+20:]
	// MSS option (kind=2, len=4)
	opts[0] = 2
	opts[1] = 4
	binary.BigEndian.PutUint16(opts[2:4], 1460)
	// SACK-Permitted (kind=4, len=2)
	opts[4] = 4
	opts[5] = 2
	// NOP
	opts[6] = 1
	opts[7] = 1
	// SACK (kind=5, len=10)
	opts[8] = 5
	opts[9] = 10
	// SACK blocks...
	binary.BigEndian.PutUint32(opts[10:14], 1000)
	binary.BigEndian.PutUint32(opts[14:18], 2000)
	// Padding
	opts[18] = 0
	opts[19] = 0

	FixIPv4Checksum(pkt[:ipHdrLen])
	FixTCPChecksum(pkt)

	return pkt
}

func TestStripSACKFromTCP_NoOptions(t *testing.T) {
	pkt := buildMinimalIPv4TCPPacket(10)
	result := StripSACKFromTCP(pkt)

	if !bytes.Equal(result, pkt) {
		t.Error("packet without options should be unchanged")
	}
}

func TestStripSACKFromTCP_WithSACK(t *testing.T) {
	pkt := buildPacketWithSACK()
	origLen := len(pkt)

	result := StripSACKFromTCP(pkt)

	// Result should be shorter (SACK options removed)
	if len(result) >= origLen {
		t.Errorf("expected shorter packet after SACK removal: orig=%d, new=%d", origLen, len(result))
	}

	// Verify TCP header is valid
	ipHdrLen := int((result[0] & 0x0F) * 4)
	tcpHdrLen := int((result[ipHdrLen+12] >> 4) * 4)
	if tcpHdrLen < 20 {
		t.Errorf("invalid TCP header length: %d", tcpHdrLen)
	}
}

func TestStripSACKFromTCPv6_NoOptions(t *testing.T) {
	pkt := buildMinimalIPv6TCPPacket(10)
	result := StripSACKFromTCPv6(pkt)

	if !bytes.Equal(result, pkt) {
		t.Error("packet without options should be unchanged")
	}
}
