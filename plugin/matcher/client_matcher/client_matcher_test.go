package client_matcher

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

func newTestMatcher(t *testing.T, args *Args) *clientMatcher {
	t.Helper()
	bp := &coremain.BP{}
	m, err := newClientMatcher(bp, args)
	if err != nil {
		t.Fatalf("newClientMatcher: %v", err)
	}
	return m
}

func matchClientIDs(m *clientMatcher, ids []string) bool {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	meta := new(query_context.RequestMeta)
	meta.SetClientIDs(ids)
	qCtx := query_context.NewContext(q, meta)
	matched, err := m.Match(context.Background(), qCtx)
	if err != nil {
		panic(err)
	}
	return matched
}

func Test_clientMatcher_any(t *testing.T) {
	m := newTestMatcher(t, &Args{ClientID: []string{"edu", "cn"}})

	cases := []struct {
		name string
		ids  []string
		want bool
	}{
		{"no ids", nil, false},
		{"empty ids", []string{}, false},
		{"hit first", []string{"edu"}, true},
		{"hit second", []string{"cn"}, true},
		{"hit among many", []string{"edu", "cn", "other"}, true},
		{"miss", []string{"other"}, false},
		{"miss with partial", []string{"ed", "c"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchClientIDs(m, c.ids); got != c.want {
				t.Fatalf("Match() = %v, want %v", got, c.want)
			}
		})
	}
}

func Test_clientMatcher_matchAll(t *testing.T) {
	m := newTestMatcher(t, &Args{ClientID: []string{"edu", "cn"}, MatchAll: true})

	cases := []struct {
		name string
		ids  []string
		want bool
	}{
		{"all present in order", []string{"edu", "cn"}, true},
		{"all present reversed", []string{"cn", "edu"}, true},
		{"all present among many", []string{"a", "edu", "b", "cn"}, true},
		{"only one of two", []string{"edu"}, false},
		{"one missing", []string{"edu", "other"}, false},
		{"none", []string{"other"}, false},
		{"no ids", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchClientIDs(m, c.ids); got != c.want {
				t.Fatalf("Match() = %v, want %v", got, c.want)
			}
		})
	}
}

func Test_clientMatcher_matchAll_single(t *testing.T) {
	m := newTestMatcher(t, &Args{ClientID: []string{"family"}, MatchAll: true})

	if !matchClientIDs(m, []string{"family"}) {
		t.Fatal("Match() = false, want true")
	}
	// match_all is a subset check: extra request ids are allowed.
	if !matchClientIDs(m, []string{"family", "extra"}) {
		t.Fatal("Match() = false, want true (extra ids allowed)")
	}
}
