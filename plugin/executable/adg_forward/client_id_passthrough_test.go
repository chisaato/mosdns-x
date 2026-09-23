/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package adg_forward

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"

	dnsproxy_upstream "github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
)

// fakeUpstream is a minimal dnsproxy upstream used to observe Close calls.
type fakeUpstream struct {
	addr  string
	close int
}

func (u *fakeUpstream) Exchange(*dns.Msg) (*dns.Msg, error) {
	return nil, errors.New("fakeUpstream: not implemented")
}

func (u *fakeUpstream) Address() string { return u.addr }

func (u *fakeUpstream) Close() error {
	u.close++
	return nil
}

func TestClientIDsKeyOrderInsensitive(t *testing.T) {
	if got, want := clientIDsKey([]string{"accel", "intl"}), "accel/intl"; got != want {
		t.Fatalf("clientIDsKey = %q, want %q", got, want)
	}
	if a, b := clientIDsKey([]string{"accel", "intl"}), clientIDsKey([]string{"intl", "accel"}); a != b {
		t.Fatalf("key should be order-insensitive: %q != %q", a, b)
	}
	if a, b := clientIDsKey([]string{"accel"}), clientIDsKey([]string{"intl"}); a == b {
		t.Fatalf("different id sets must not collide: %q == %q", a, b)
	}
	if got := clientIDsKey(nil); got != "" {
		t.Fatalf("empty ids key = %q, want empty", got)
	}
}

func TestBuildVariantAddr(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		ids     []string
		wantRaw string // exact url string (escaped)
		wantDec string // decoded path
	}{
		{
			name:    "basic",
			base:    "https://hub.example:4215/dns-query",
			ids:     []string{"accel", "international"},
			wantRaw: "https://hub.example:4215/dns-query/accel/international",
			wantDec: "/dns-query/accel/international",
		},
		{
			name:    "trailing slash base",
			base:    "https://hub.example:4215/dns-query/",
			ids:     []string{"accel"},
			wantRaw: "https://hub.example:4215/dns-query/accel",
			wantDec: "/dns-query/accel",
		},
		{
			name:    "empty base path",
			base:    "https://hub.example:4215",
			ids:     []string{"accel"},
			wantRaw: "https://hub.example:4215/accel",
			wantDec: "/accel",
		},
		{
			name:    "ids needing escaping stay single segments",
			base:    "https://hub.example:4215/dns-query",
			ids:     []string{"a/b", "c d"},
			wantRaw: "https://hub.example:4215/dns-query/a%2Fb/c%20d",
			wantDec: "/dns-query/a/b/c d",
		},
		{
			name:    "single id",
			base:    "https://hub.example:4215/dns-query",
			ids:     []string{"accel"},
			wantRaw: "https://hub.example:4215/dns-query/accel",
			wantDec: "/dns-query/accel",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildVariantAddr(tc.base, tc.ids)
			if err != nil {
				t.Fatalf("buildVariantAddr() error = %v", err)
			}
			if got != tc.wantRaw {
				t.Fatalf("buildVariantAddr() = %q, want %q", got, tc.wantRaw)
			}

			// Path (decoded) and RawPath (escaped) must stay consistent.
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parsing result: %v", err)
			}
			if u.Path != tc.wantDec {
				t.Fatalf("decoded path = %q, want %q", u.Path, tc.wantDec)
			}
			want, err := url.Parse(tc.wantRaw)
			if err != nil {
				t.Fatalf("parsing want: %v", err)
			}
			if u.EscapedPath() != want.EscapedPath() {
				t.Fatalf("escaped path = %q, want %q", u.EscapedPath(), want.EscapedPath())
			}
		})
	}
}

func TestBuildVariantAddrInvalid(t *testing.T) {
	if _, err := buildVariantAddr("://not a url", []string{"x"}); err == nil {
		t.Fatal("expected error for invalid url")
	}
}

// newTestForward builds a bare adgForward sufficient for upstream variant tests.
func newTestForward(t *testing.T, cacheSize int) *adgForward {
	t.Helper()
	f := &adgForward{
		args: &Args{
			Upstream: []UpstreamConfig{
				{Addr: "https://127.0.0.1:9/dns-query"},
			},
		},
		timeout: time.Second,
	}
	// base group is a stub; variant tests only compare returned group identity.
	f.rawUpstreams = []dnsproxy_upstream.Upstream{&fakeUpstream{addr: "base"}}
	f.upstreamsCloser = append(f.upstreamsCloser, f.rawUpstreams...)

	if cacheSize > 0 {
		f.passthroughCache = concurrent_lru.NewConecurrentLRU[string, []dnsproxy_upstream.Upstream](
			cacheSize,
			func(_ string, ups []dnsproxy_upstream.Upstream) {},
		)
	}
	return f
}

func TestUpstreamsForIDs(t *testing.T) {
	f := newTestForward(t, defaultPassthroughCacheSize)

	// Empty ids -> base group, no variant build.
	base, err := f.upstreamsForIDs(nil)
	if err != nil {
		t.Fatalf("upstreamsForIDs(nil) error = %v", err)
	}
	if len(base) != 1 || base[0] != f.rawUpstreams[0] {
		t.Fatalf("empty ids should return base upstreams")
	}
	if f.passthroughCache.Len() != 0 {
		t.Fatalf("empty ids must not populate cache, len = %d", f.passthroughCache.Len())
	}

	// First build.
	first, err := f.upstreamsForIDs([]string{"accel", "intl"})
	if err != nil {
		t.Fatalf("upstreamsForIDs() error = %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("variant group size = %d, want 1", len(first))
	}
	if got, want := first[0].Address(), "https://127.0.0.1:9/dns-query/accel/intl"; got != want {
		t.Fatalf("variant addr = %q, want %q", got, want)
	}

	// Reversed order must reuse the same group (built only once).
	second, err := f.upstreamsForIDs([]string{"intl", "accel"})
	if err != nil {
		t.Fatalf("upstreamsForIDs() error = %v", err)
	}
	if first[0] != second[0] {
		t.Fatalf("reversed ids should reuse the cached group")
	}
	if f.passthroughCache.Len() != 1 {
		t.Fatalf("cache len = %d, want 1", f.passthroughCache.Len())
	}
}

func TestUpstreamsForIDsEviction(t *testing.T) {
	const cacheSize = 2
	f := newTestForward(t, cacheSize)

	for _, ids := range [][]string{{"a"}, {"b"}, {"c"}} {
		if _, err := f.upstreamsForIDs(ids); err != nil {
			t.Fatalf("upstreamsForIDs(%v) error = %v", ids, err)
		}
	}
	if got := f.passthroughCache.Len(); got != cacheSize {
		t.Fatalf("cache len = %d, want %d", got, cacheSize)
	}
}

// TestUpstreamGroupEvictionClose verifies the production onEvict helper closes
// evicted upstream groups.
func TestUpstreamGroupEvictionClose(t *testing.T) {
	cache := concurrent_lru.NewConecurrentLRU[string, []dnsproxy_upstream.Upstream](
		2,
		func(_ string, ups []dnsproxy_upstream.Upstream) { closeUpstreamGroup(ups) },
	)

	a := &fakeUpstream{addr: "a"}
	b := &fakeUpstream{addr: "b"}
	c := &fakeUpstream{addr: "c"}
	cache.Add("a", []dnsproxy_upstream.Upstream{a})
	cache.Add("b", []dnsproxy_upstream.Upstream{b})
	cache.Add("c", []dnsproxy_upstream.Upstream{c})

	if a.close != 1 {
		t.Fatalf("evicted upstream 'a' close count = %d, want 1", a.close)
	}
	if b.close != 0 || c.close != 0 {
		t.Fatalf("surviving upstreams must not be closed: b=%d c=%d", b.close, c.close)
	}
}
