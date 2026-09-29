package ecs

import (
	"net/netip"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

// Ranges that are not private in netip's sense but cannot locate a client
// on the public internet either.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, also Tailscale
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking, also proxy fake-ip / tun
}

// isPublicAddr reports whether addr can locate a client for ECS.
// Loopback, private, link-local and the ranges above cannot: an upstream
// either ignores such an ECS (and answers by its own view of us anyway) or,
// like Google, refuses the query.
func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// dropNonPublicECS removes an ECS in opt whose address is not public, e.g.
// one added by dnsmasq add-subnet on a LAN. A /0 ECS is the client opting
// out of ECS and is kept.
func dropNonPublicECS(opt *dns.OPT) {
	ecs := dnsutils.GetECS(opt)
	if ecs == nil || ecs.SourceNetmask == 0 {
		return
	}
	if addr, ok := netip.AddrFromSlice(ecs.Address); ok && isPublicAddr(addr) {
		return
	}
	dnsutils.RemoveECS(opt)
}
