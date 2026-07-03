package adg_cache

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

func Test_adgCachePlugin_getCacheKey_uses_same_key_for_same_ipv4_ecs_prefix(t *testing.T) {
	// Given
	p := &adgCachePlugin{}
	first := newQueryWithECS(t, "example.com.", net.IPv4(1, 2, 3, 4), 24, false)
	second := newQueryWithECS(t, "example.com.", net.IPv4(1, 2, 3, 99), 24, false)

	// When
	firstKey, firstErr := p.getCacheKey(first, "")
	secondKey, secondErr := p.getCacheKey(second, "")

	// Then
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)
	require.Equal(t, firstKey, secondKey)
}

func Test_adgCachePlugin_getCacheKey_uses_same_key_for_same_ipv6_ecs_prefix(t *testing.T) {
	// Given
	p := &adgCachePlugin{}
	first := newQueryWithECS(t, "example.com.", net.ParseIP("2001:db8:1234:5601::1"), 56, true)
	second := newQueryWithECS(t, "example.com.", net.ParseIP("2001:db8:1234:56ff::1"), 56, true)

	// When
	firstKey, firstErr := p.getCacheKey(first, "")
	secondKey, secondErr := p.getCacheKey(second, "")

	// Then
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)
	require.Equal(t, firstKey, secondKey)
}

func Test_adgCachePlugin_getCacheKey_uses_distinct_key_for_distinct_ipv4_ecs_prefix(t *testing.T) {
	// Given
	p := &adgCachePlugin{}
	first := newQueryWithECS(t, "example.com.", net.IPv4(1, 2, 3, 4), 24, false)
	second := newQueryWithECS(t, "example.com.", net.IPv4(1, 2, 4, 4), 24, false)

	// When
	firstKey, firstErr := p.getCacheKey(first, "")
	secondKey, secondErr := p.getCacheKey(second, "")

	// Then
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)
	require.NotEqual(t, firstKey, secondKey)
}

func newQueryWithECS(t *testing.T, name string, ip net.IP, mask uint8, v6 bool) *dns.Msg {
	t.Helper()

	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	opt := dnsutils.UpgradeEDNS0(m)
	added := dnsutils.AddECS(opt, dnsutils.NewEDNS0Subnet(ip, mask, v6), true)
	require.True(t, added)
	return m
}

func Test_adgCachePlugin_doPrefetch_does_not_carry_stale_response_to_next_node(t *testing.T) {
	// Given
	prefetchCtx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p := &adgCachePlugin{
		prefetchCtx: prefetchCtx,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q, nil)
	qCtx.SetResponse(newAResponse(q, net.IPv4(192, 0, 2, 1), 30))

	seenResponse := make(chan bool, 1)
	next := executable_seq.WrapExecutable(responseProbe{seenResponse: seenResponse})

	// When
	p.doPrefetch("prefetch-key", qCtx, next)

	// Then
	select {
	case carriedResponse := <-seenResponse:
		require.False(t, carriedResponse)
	case <-time.After(time.Second):
		t.Fatal("prefetch did not execute next node")
	}
}

func newAResponse(q *dns.Msg, ip net.IP, ttl uint32) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: ip,
	})
	return r
}

type responseProbe struct {
	seenResponse chan<- bool
}

func (p responseProbe) Exec(_ context.Context, qCtx *query_context.Context, _ executable_seq.ExecutableChainNode) error {
	p.seenResponse <- qCtx.R() != nil
	return nil
}
