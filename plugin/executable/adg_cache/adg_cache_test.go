package adg_cache

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/pmkol/mosdns-x/coremain"
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

func Test_adgCachePlugin_doRefresh_does_not_carry_stale_response_to_next_node(t *testing.T) {
	// Given
	prefetchCtx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p := &adgCachePlugin{
		metrics:     newCacheMetrics(),
		prefetchCtx: prefetchCtx,
	}

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q, nil)
	qCtx.SetResponse(newAResponse(q, net.IPv4(192, 0, 2, 1), 30))

	seenResponse := make(chan bool, 1)
	next := executable_seq.WrapExecutable(responseProbe{seenResponse: seenResponse})

	// When
	p.doRefresh("prefetch-key", qCtx, next)

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

// upstreamStub answers with a fixed A record and reports each call.
type upstreamStub struct {
	ip    net.IP
	ttl   uint32
	calls chan struct{}
}

func (u upstreamStub) Exec(_ context.Context, qCtx *query_context.Context, _ executable_seq.ExecutableChainNode) error {
	qCtx.SetResponse(newAResponse(qCtx.Q(), u.ip, u.ttl))
	u.calls <- struct{}{}
	return nil
}

func newTestCache(t *testing.T, args *Args) *adgCachePlugin {
	t.Helper()
	p, err := newAdgCachePlugin(coremain.NewBP("test", PluginType, nil, nil), args)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// seedEntry stores an A answer of cachedTTL for q that expires at
// now+expiresIn (negative means already expired).
func seedEntry(t *testing.T, p *adgCachePlugin, q *dns.Msg, cachedTTL uint32, expiresIn int64) {
	t.Helper()
	key, err := p.getCacheKey(q, "")
	require.NoError(t, err)
	packed, err := newAResponse(q, net.IPv4(192, 0, 2, 1), cachedTTL).Pack()
	require.NoError(t, err)
	expiry := uint32(time.Now().Unix() + expiresIn)
	p.items.Set([]byte(key), packCacheValue(expiry, packed))
}

func execCache(t *testing.T, p *adgCachePlugin, q *dns.Msg, next upstreamStub) *dns.Msg {
	t.Helper()
	qCtx := query_context.NewContext(q, nil)
	require.NoError(t, p.Exec(context.Background(), qCtx, executable_seq.WrapExecutable(next)))
	require.NotNil(t, qCtx.R())
	return qCtx.R()
}

func answerIP(r *dns.Msg) string {
	return r.Answer[0].(*dns.A).A.String()
}

func waitCall(t *testing.T, calls chan struct{}, want bool) {
	t.Helper()
	select {
	case <-calls:
		require.True(t, want, "next was called unexpectedly")
	case <-time.After(200 * time.Millisecond):
		require.False(t, want, "next was not called")
	}
}

func Test_adgCachePlugin_stale_hit_serves_stale_and_refreshes(t *testing.T) {
	p := newTestCache(t, &Args{})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	seedEntry(t, p, q, 300, -5)
	next := upstreamStub{ip: net.IPv4(198, 51, 100, 1), ttl: 300, calls: make(chan struct{}, 4)}

	// Stale answer is served right away, the refresh runs in the background.
	r := execCache(t, p, q, next)
	require.Equal(t, "192.0.2.1", answerIP(r))
	require.EqualValues(t, defaultOptimisticTTL, r.Answer[0].Header().Ttl)
	waitCall(t, next.calls, true)

	// The refreshed entry is served fresh.
	require.Eventually(t, func() bool {
		return answerIP(execCache(t, p, q, next)) == "198.51.100.1"
	}, time.Second, 10*time.Millisecond)
}

func Test_adgCachePlugin_short_ttl_not_served_stale(t *testing.T) {
	tests := []struct {
		name        string
		args        *Args
		cachedTTL   uint32
		wantStaleIP bool
	}{
		{"ttl within optimistic_ttl: miss", &Args{}, 30, false},
		{"ttl above optimistic_ttl: stale", &Args{}, 31, true},
		{"stale_min_ttl disabled: stale", &Args{StaleMinTTL: -1}, 30, true},
		{"optimistic false: miss", &Args{Optimistic: new(bool)}, 300, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestCache(t, tt.args)
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			seedEntry(t, p, q, tt.cachedTTL, -5)
			next := upstreamStub{ip: net.IPv4(198, 51, 100, 1), ttl: 300, calls: make(chan struct{}, 4)}

			r := execCache(t, p, q, next)
			if tt.wantStaleIP {
				require.Equal(t, "192.0.2.1", answerIP(r))
			} else {
				require.Equal(t, "198.51.100.1", answerIP(r))
			}
		})
	}
}

func Test_adgCachePlugin_prefetch_before_expiry(t *testing.T) {
	tests := []struct {
		name      string
		prefetch  bool
		cachedTTL uint32
		expiresIn int64
		wantCall  bool
	}{
		{"within window: refresh", true, 300, 5, true},
		{"outside window: no refresh", true, 300, 100, false},
		{"whole ttl within window: no refresh", true, 8, 5, false},
		{"prefetch off: no refresh", false, 300, 5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestCache(t, &Args{Prefetch: tt.prefetch})
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			seedEntry(t, p, q, tt.cachedTTL, tt.expiresIn)
			next := upstreamStub{ip: net.IPv4(198, 51, 100, 1), ttl: 300, calls: make(chan struct{}, 4)}

			r := execCache(t, p, q, next)
			require.Equal(t, "192.0.2.1", answerIP(r))
			waitCall(t, next.calls, tt.wantCall)
		})
	}
}

func Test_adgCachePlugin_metrics(t *testing.T) {
	p := newTestCache(t, &Args{})
	next := upstreamStub{ip: net.IPv4(198, 51, 100, 1), ttl: 300, calls: make(chan struct{}, 4)}

	fresh := new(dns.Msg)
	fresh.SetQuestion("fresh.example.", dns.TypeA)
	seedEntry(t, p, fresh, 300, 100)
	stale := new(dns.Msg)
	stale.SetQuestion("stale.example.", dns.TypeA)
	seedEntry(t, p, stale, 300, -5)
	miss := new(dns.Msg)
	miss.SetQuestion("miss.example.", dns.TypeA)

	execCache(t, p, fresh, next)
	execCache(t, p, stale, next)
	waitCall(t, next.calls, true) // stale refresh
	execCache(t, p, miss, next)
	waitCall(t, next.calls, true)

	m := p.metrics
	require.EqualValues(t, 3, counterValue(t, m.queryTotal))
	require.EqualValues(t, 1, counterValue(t, m.hitTotal))
	require.EqualValues(t, 1, counterValue(t, m.staleHitTotal))
	require.EqualValues(t, 1, counterValue(t, m.refreshTotal))
}

func Test_adgCachePlugin_onEvict_counts_live_entries(t *testing.T) {
	p := newTestCache(t, &Args{StaleTTL: 300})
	now := time.Now().Unix()
	val := func(expiresIn int64) []byte { return packCacheValue(uint32(now+expiresIn), []byte{0}) }

	p.onEvict(nil, val(100))  // fresh
	p.onEvict(nil, val(-100)) // stale but servable
	p.onEvict(nil, val(-400)) // past stale_ttl, dead weight

	require.EqualValues(t, 3, counterValue(t, p.metrics.evictedTotal))
	require.EqualValues(t, 2, counterValue(t, p.metrics.evictedLiveTotal))
}

func Test_adgCachePlugin_lru_eviction_calls_onEvict(t *testing.T) {
	p := newTestCache(t, &Args{Size: 1024})
	for i := 0; i < 20; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("host%d.example.", i), dns.TypeA)
		seedEntry(t, p, q, 300, 100)
	}
	require.Positive(t, counterValue(t, p.metrics.evictedTotal))
	require.Equal(t, counterValue(t, p.metrics.evictedTotal), counterValue(t, p.metrics.evictedLiveTotal))
	require.LessOrEqual(t, p.items.Stats().Size, 1024)
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}
