package sock

import "encoding/binary"

// IPv4FragmentPacket creates IPv4 IP-level fragments.
// splitPos is relative to the IP payload (bytes after the IP header).
func IPv4FragmentPacket(packet []byte, splitPos int) ([][]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil, false
	}

	ipHdrLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHdrLen+8 {
		return nil, false
	}

	ipPayloadLen := len(packet) - ipHdrLen
	if ipPayloadLen < 8 {
		return nil, false
	}

	// Align to 8-byte boundary (required by IP fragmentation)
	splitPos = (splitPos + 7) &^ 7
	if splitPos < 8 {
		splitPos = 8
	}
	if splitPos >= ipPayloadLen {
		splitPos = ipPayloadLen - 8
		splitPos = splitPos &^ 7
		if splitPos < 8 {
			return nil, false
		}
	}

	absPos := ipHdrLen + splitPos

	// Fragment 1: IP header + first splitPos bytes of IP payload, MF flag set
	frag1 := make([]byte, absPos)
	copy(frag1, packet[:absPos])
	frag1[6] = 0x20
	frag1[7] = 0x00
	binary.BigEndian.PutUint16(frag1[2:4], uint16(absPos))
	FixIPv4Checksum(frag1[:ipHdrLen])

	// Fragment 2: IP header + remaining data, with fragment offset
	remainingLen := len(packet) - absPos
	frag2Len := ipHdrLen + remainingLen
	frag2 := make([]byte, frag2Len)
	copy(frag2, packet[:ipHdrLen])
	copy(frag2[ipHdrLen:], packet[absPos:])
	fragOff := uint16(splitPos) / 8
	binary.BigEndian.PutUint16(frag2[6:8], fragOff)
	binary.BigEndian.PutUint16(frag2[2:4], uint16(frag2Len))
	FixIPv4Checksum(frag2[:ipHdrLen])

	return [][]byte{frag1, frag2}, true
}
