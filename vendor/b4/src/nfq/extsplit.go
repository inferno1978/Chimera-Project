package nfq

import (
	"encoding/binary"
	"net"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sock"
)

// findPreSNIExtensionPoint finds a good split point BEFORE the SNI extension
// This exploits DPI that only parses complete extensions
func findPreSNIExtensionPoint(payload []byte) int {
	if len(payload) < 5 || payload[0] != 0x16 {
		return -1
	}

	pos := 5

	if pos+4 > len(payload) || payload[pos] != 0x01 {
		return -1
	}
	pos += 4

	if pos+34 > len(payload) {
		return -1
	}
	pos += 34

	if pos >= len(payload) {
		return -1
	}
	sidLen := int(payload[pos])
	pos++
	pos += sidLen

	if pos+2 > len(payload) {
		return -1
	}
	csLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + csLen

	if pos >= len(payload) {
		return -1
	}
	compLen := int(payload[pos])
	pos++
	pos += compLen

	if pos+2 > len(payload) {
		return -1
	}
	extLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	extStart := pos
	extEnd := pos + extLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	lastSafePos := extStart
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))

		if extType == 0 {
			return lastSafePos
		}

		lastSafePos = pos
		pos += 4 + extDataLen
	}

	return -1
}

func (w *Worker) sendExtSplitFragments(cfg *config.SetConfig, packet []byte, dst net.IP) {
	pi, ok := ExtractPacketInfoV4(packet)
	if !ok || pi.PayloadLen < 50 {
		_ = w.sock.SendIPv4(packet, dst)
		return
	}

	splitPos := findPreSNIExtensionPoint(pi.Payload)

	if splitPos <= 5 || splitPos >= pi.PayloadLen-10 {
		w.sendTCPFragments(cfg, packet, dst)
		return
	}

	// Segment 1: everything before SNI extension
	seg1 := BuildSegmentV4(packet, pi, pi.Payload[:splitPos], 0, 0)
	ClearPSH(seg1, pi.IPHdrLen)
	sock.FixTCPChecksum(seg1)

	// Segment 2: SNI extension onwards
	seg2 := BuildSegmentV4(packet, pi, pi.Payload[splitPos:], uint32(splitPos), 1)

	delay := config.ResolveSeg2Delay(cfg.TCP.Seg2Delay, cfg.TCP.Seg2DelayMax)

	w.SendTwoSegmentsV4(seg1, seg2, dst, delay, cfg.Fragmentation.ReverseOrder)
}
