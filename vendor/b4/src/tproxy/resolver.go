package tproxy

import (
	"net"
	"sync/atomic"

	"github.com/daniellavrushin/b4/sni"
)

type LearnedIPResolver struct {
	matcher atomic.Pointer[sni.SuffixSet]
}

func NewLearnedIPResolver(m *sni.SuffixSet) *LearnedIPResolver {
	r := &LearnedIPResolver{}
	r.matcher.Store(m)
	return r
}

func (r *LearnedIPResolver) Set(m *sni.SuffixSet) {
	r.matcher.Store(m)
}

func (r *LearnedIPResolver) DomainFor(ip net.IP) string {
	m := r.matcher.Load()
	if m == nil || ip == nil {
		return ""
	}
	matched, _, domain := m.MatchLearnedIP(ip)
	if !matched {
		return ""
	}
	return domain
}
