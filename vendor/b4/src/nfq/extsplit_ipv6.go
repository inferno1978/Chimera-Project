package nfq

import (
	"net"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sock"
)

// sendExtSplitFragmentsV6 - IPv6 version: splits before SNI extension
func (w *Worker) sendExtSplitFragmentsV6(cfg *config.SetConfig, packet []byte, dst net.IP) {
	pi, ok := ExtractPacketInfoV6(packet)
	if !ok || pi.PayloadLen < 50 {
		_ = w.sock.SendIPv6(packet, dst)
		return
	}

	splitPos := findPreSNIExtensionPoint(pi.Payload)

	if splitPos <= 5 || splitPos >= pi.PayloadLen-10 {
		w.sendTCPSegmentsv6(cfg, packet, dst)
		return
	}

	// Segment 1: everything before SNI extension
	seg1 := BuildSegmentV6(packet, pi, pi.Payload[:splitPos], 0)
	ClearPSH(seg1, pi.IPHdrLen)
	sock.FixTCPChecksumV6(seg1)

	// Segment 2: SNI extension onwards
	seg2 := BuildSegmentV6(packet, pi, pi.Payload[splitPos:], uint32(splitPos))

	delay := config.ResolveSeg2Delay(cfg.TCP.Seg2Delay, cfg.TCP.Seg2DelayMax)

	w.SendTwoSegmentsV6(seg1, seg2, dst, delay, cfg.Fragmentation.ReverseOrder)
}
