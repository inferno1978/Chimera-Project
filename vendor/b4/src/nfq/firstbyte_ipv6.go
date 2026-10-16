package nfq

import (
	"net"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sock"
)

func (w *Worker) sendFirstByteDesyncV6(cfg *config.SetConfig, packet []byte, dst net.IP) {
	pi, ok := ExtractPacketInfoV6(packet)
	if !ok || pi.PayloadLen < 2 {
		_ = w.sock.SendIPv6(packet, dst)
		return
	}

	// Segment 1: Just first byte
	seg1 := BuildSegmentV6(packet, pi, pi.Payload[:1], 0)
	ClearPSH(seg1, pi.IPHdrLen)
	sock.FixTCPChecksumV6(seg1)

	// Segment 2: Rest
	seg2 := BuildSegmentV6(packet, pi, pi.Payload[1:], 1)

	_ = w.sock.SendIPv6(seg1, dst)

	delay := config.ResolveSeg2Delay(cfg.TCP.Seg2Delay, cfg.TCP.Seg2DelayMax)
	if delay < 10 {
		delay = 30
	}

	jitter := int(pi.Seq0 % uint32(delay/3+1))
	time.Sleep(time.Duration(delay+jitter) * time.Millisecond)

	_ = w.sock.SendIPv6(seg2, dst)
}
