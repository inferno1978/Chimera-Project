package sock

import (
	crand "crypto/rand"
	"encoding/binary"
)

const (
	quicFakeHeaderLen = 30
	quicFakeMaxSize   = quicFakeHeaderLen + 0x3FFF - 4
)

func BuildQUICInitial(size int) []byte {
	if size < quicFakeHeaderLen || size > quicFakeMaxSize {
		return nil
	}
	out := make([]byte, size)

	out[0] = 0xC3

	out[1] = 0x00
	out[2] = 0x00
	out[3] = 0x00
	out[4] = 0x01

	out[5] = 0x08
	if _, err := crand.Read(out[6:14]); err != nil {
		return nil
	}

	out[14] = 0x08
	if _, err := crand.Read(out[15:23]); err != nil {
		return nil
	}

	out[23] = 0x00

	out[26] = 0x00
	out[27] = 0x00
	out[28] = 0x00
	out[29] = 0x00

	if size > quicFakeHeaderLen {
		if _, err := crand.Read(out[quicFakeHeaderLen:]); err != nil {
			return nil
		}
	}

	coveredLen := 4 + (size - quicFakeHeaderLen)
	binary.BigEndian.PutUint16(out[24:26], 0x4000|uint16(coveredLen))

	return out
}
