package sock

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func BenchmarkBuildFakeSNIPacketV4(b *testing.B) {
	pkt := buildMinimalIPv4TCPPacket(100)
	cfg := &config.SetConfig{}
	cfg.Faking.Strategy = "ttl"
	cfg.Faking.TTL = 3

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildFakeSNIPacketV4(pkt, cfg)
	}
}

func BenchmarkFixIPv4Checksum(b *testing.B) {
	pkt := buildMinimalIPv4TCPPacket(100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FixIPv4Checksum(pkt[:20])
	}
}

func BenchmarkFixTCPChecksum(b *testing.B) {
	pkt := buildMinimalIPv4TCPPacket(500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FixTCPChecksum(pkt)
	}
}

func BenchmarkStripSACKFromTCP(b *testing.B) {
	pkt := buildPacketWithSACK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		StripSACKFromTCP(pkt)
	}
}
