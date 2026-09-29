/*
 * Copyright (C) 2020-2026, pmkol
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

package tunnel_accelerate

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

// nextRecorder is a chain tail that records whether it was invoked.
type nextRecorder struct {
	executable_seq.NodeLinker
	called bool
}

func (n *nextRecorder) Exec(_ context.Context, _ *query_context.Context, _ executable_seq.ExecutableChainNode) error {
	n.called = true
	return nil
}

// fakeDialer injects probe results: ips in the dead set fail to dial.
type fakeDialer struct {
	dead  map[string]bool
	ports map[string]int
}

func (f *fakeDialer) probe(_ context.Context, ip string, port int, _ time.Duration) bool {
	if f.ports != nil {
		f.ports[ip] = port
	}
	return !f.dead[ip]
}

func newTestPlugin(t *testing.T, hostsEntry string, dead []string) *tunnelAccelerate {
	t.Helper()

	args := &Args{Hosts: []string{hostsEntry}}
	p, err := newTunnelAccelerate(coremain.NewBP("test", PluginType, nil, nil), args)
	if err != nil {
		t.Fatalf("failed to init plugin: %v", err)
	}
	deadSet := make(map[string]bool, len(dead))
	for _, ip := range dead {
		deadSet[ip] = true
	}
	f := &fakeDialer{dead: deadSet}
	p.dialProbe = f.probe
	return p
}

func Test_tunnelAccelerate_Exec(t *testing.T) {
	tests := []struct {
		name         string
		hostsEntry   string
		qtype        uint16
		dead         []string
		wantPass     bool     // next should be called (fall through)
		wantAnswers  []string // expected answer IPs, empty means empty answer
		wantEmpty    bool     // expect empty NOERROR answer
		wantTakeOver bool     // plugin should take over (next not called)
	}{
		{
			name:         "miss hosts: pass through",
			hostsEntry:   "other.com. 1.1.1.1",
			qtype:        dns.TypeA,
			wantPass:     true,
			wantTakeOver: false,
		},
		{
			name:         "A: partial alive, reply alive ips only",
			hostsEntry:   "example.com. 1.1.1.1 2.2.2.2",
			qtype:        dns.TypeA,
			dead:         []string{"2.2.2.2"},
			wantAnswers:  []string{"1.1.1.1"},
			wantTakeOver: true,
		},
		{
			name:         "A: v4 all dead but v6 alive, suppress this family",
			hostsEntry:   "example.com. 1.1.1.1 fd00::1",
			qtype:        dns.TypeA,
			dead:         []string{"1.1.1.1"},
			wantEmpty:    true,
			wantTakeOver: true,
		},
		{
			name:         "A: v4 all dead and no v6, fall through",
			hostsEntry:   "example.com. 1.1.1.1",
			qtype:        dns.TypeA,
			dead:         []string{"1.1.1.1"},
			wantPass:     true,
			wantTakeOver: false,
		},
		{
			name:         "A: all families dead, fall through",
			hostsEntry:   "example.com. 1.1.1.1 fd00::1",
			qtype:        dns.TypeA,
			dead:         []string{"1.1.1.1", "fd00::1"},
			wantPass:     true,
			wantTakeOver: false,
		},
		{
			name:         "TYPE65: any alive, empty NOERROR",
			hostsEntry:   "example.com. 1.1.1.1 fd00::1",
			qtype:        dns.TypeHTTPS,
			dead:         []string{"1.1.1.1"},
			wantEmpty:    true,
			wantTakeOver: true,
		},
		{
			name:         "TYPE65: all dead, pass through",
			hostsEntry:   "example.com. 1.1.1.1 fd00::1",
			qtype:        dns.TypeHTTPS,
			dead:         []string{"1.1.1.1", "fd00::1"},
			wantPass:     true,
			wantTakeOver: false,
		},
		{
			name:         "AAAA: partial alive, reply alive ips only",
			hostsEntry:   "example.com. fd00::1 fd00::2",
			qtype:        dns.TypeAAAA,
			dead:         []string{"fd00::2"},
			wantAnswers:  []string{"fd00::1"},
			wantTakeOver: true,
		},
		{
			name:         "AAAA: v6 all dead but v4 alive, suppress this family",
			hostsEntry:   "example.com. 1.1.1.1 fd00::1",
			qtype:        dns.TypeAAAA,
			dead:         []string{"fd00::1"},
			wantEmpty:    true,
			wantTakeOver: true,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPlugin(t, tt.hostsEntry, tt.dead)

			q := new(dns.Msg)
			q.SetQuestion("example.com", tt.qtype)
			qCtx := query_context.NewContext(q, nil)
			next := &nextRecorder{}

			if err := p.Exec(ctx, qCtx, next); err != nil {
				t.Fatalf("Exec() error: %v", err)
			}

			if next.called != tt.wantPass {
				t.Fatalf("next called = %v, want %v", next.called, tt.wantPass)
			}
			if tt.wantTakeOver == tt.wantPass {
				t.Fatalf("invalid test case: wantTakeOver and wantPass must differ")
			}

			r := qCtx.R()
			if !tt.wantTakeOver {
				if r != nil {
					t.Fatalf("expected no response, but got %v", r)
				}
				return
			}
			if r == nil {
				t.Fatal("expected a response, but got nil")
			}
			if r.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %d, want %d", r.Rcode, dns.RcodeSuccess)
			}

			if tt.wantEmpty {
				if len(r.Answer) != 0 {
					t.Fatalf("expected empty NOERROR, but got %d answers", len(r.Answer))
				}
				return
			}

			// Verify answer records: type and ip set.
			if len(r.Answer) != len(tt.wantAnswers) {
				t.Fatalf("answer count = %d, want %d", len(r.Answer), len(tt.wantAnswers))
			}
			gotIPs := make(map[string]bool)
			for _, rr := range r.Answer {
				var ip netip.Addr
				switch v := rr.(type) {
				case *dns.A:
					if tt.qtype != dns.TypeA {
						t.Fatalf("unexpected record type %T for qtype %d", rr, tt.qtype)
					}
					ip, _ = netip.AddrFromSlice(v.A)
				case *dns.AAAA:
					if tt.qtype != dns.TypeAAAA {
						t.Fatalf("unexpected record type %T for qtype %d", rr, tt.qtype)
					}
					ip, _ = netip.AddrFromSlice(v.AAAA)
				default:
					t.Fatalf("unexpected record type %T", rr)
				}
				if rr.Header().Ttl != uint32(p.args.TTL) {
					t.Fatalf("record ttl = %d, want %d", rr.Header().Ttl, p.args.TTL)
				}
				gotIPs[ip.String()] = true
			}
			for _, want := range tt.wantAnswers {
				if !gotIPs[strings.ToLower(want)] {
					t.Fatalf("answer missing ip %s, got %v", want, gotIPs)
				}
			}
		})
	}
}

// Test_probePortFor verifies the per-FQDN probe port override.
func Test_probePortFor(t *testing.T) {
	p := newTestPlugin(t, "example.com. 1.1.1.1", nil)
	p.args.ProbePort = 443
	p.probePortMap = map[string]int{
		"override.com.": 8443,
	}

	if got := p.probePortFor("example.com."); got != 443 {
		t.Fatalf("probe port = %d, want 443", got)
	}
	if got := p.probePortFor("override.com."); got != 8443 {
		t.Fatalf("probe port = %d, want 8443", got)
	}
}

// Test_probeIP_cached verifies that the probe cache serves repeated lookups
// without re-dialing.
func Test_probeIP_cached(t *testing.T) {
	p := newTestPlugin(t, "example.com. 1.1.1.1", nil)

	calls := 0
	p.dialProbe = func(_ context.Context, _ string, _ int, _ time.Duration) bool {
		calls++
		return true
	}

	ip := netip.MustParseAddr("1.1.1.1")
	for i := 0; i < 3; i++ {
		if !p.probeIP(context.Background(), ip, 443) {
			t.Fatal("probe should be alive")
		}
	}
	if calls != 1 {
		t.Fatalf("dial called %d times, want 1 (cached)", calls)
	}
}

// responder is a chain tail that answers with a fixed-ttl record, standing in
// for public resolution.
type responder struct {
	executable_seq.NodeLinker
	ttl uint32
}

func (n *responder) Exec(_ context.Context, qCtx *query_context.Context, _ executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = append(r.Answer, &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: n.ttl},
		Priority: 1,
		Target:   ".",
	}})
	qCtx.SetResponse(r)
	return nil
}

// Test_fallThrough_capsTTL verifies that the public fallback answer of a
// registered domain does not outlive the probe decision, while unregistered
// domains are left untouched.
func Test_fallThrough_capsTTL(t *testing.T) {
	tests := []struct {
		name       string
		hostsEntry string
		qtype      uint16
		dead       []string
		wantTTL    uint32
	}{
		{"registered, all dead, TYPE65", "example.com. 1.1.1.1", dns.TypeHTTPS, []string{"1.1.1.1"}, 30},
		{"registered, qtype not probed", "example.com. 1.1.1.1", dns.TypeMX, nil, 30},
		{"not registered", "other.com. 1.1.1.1", dns.TypeHTTPS, nil, 300},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPlugin(t, tt.hostsEntry, tt.dead)
			q := new(dns.Msg)
			q.SetQuestion("example.com.", tt.qtype)
			qCtx := query_context.NewContext(q, nil)
			if err := p.Exec(context.Background(), qCtx, &responder{ttl: 300}); err != nil {
				t.Fatalf("Exec() error: %v", err)
			}
			r := qCtx.R()
			if r == nil || len(r.Answer) != 1 {
				t.Fatalf("expected the fallback answer, got %v", r)
			}
			if got := r.Answer[0].Header().Ttl; got != tt.wantTTL {
				t.Fatalf("ttl = %d, want %d", got, tt.wantTTL)
			}
		})
	}
}

// Test_probeIP_canceledCtxNotCached verifies that a query whose ctx is already
// done does not cache a "dead" verdict for a healthy endpoint.
func Test_probeIP_canceledCtxNotCached(t *testing.T) {
	p := newTestPlugin(t, "example.com. 1.1.1.1", nil)
	p.dialProbe = func(ctx context.Context, _ string, _ int, _ time.Duration) bool {
		return ctx.Err() == nil // a real dial fails on a done ctx
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_ = p.Exec(canceled, query_context.NewContext(q, nil), &nextRecorder{})

	q = new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(q, nil)
	next := &nextRecorder{}
	if err := p.Exec(context.Background(), qCtx, next); err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if next.called || qCtx.R() == nil || len(qCtx.R().Answer) != 1 {
		t.Fatalf("healthy endpoint should be taken over after a canceled query, next called = %v", next.called)
	}
}

// Test_probeIP_singleflight verifies that concurrent misses on the same
// endpoint share one dial.
func Test_probeIP_singleflight(t *testing.T) {
	p := newTestPlugin(t, "example.com. 1.1.1.1", nil)
	var calls atomic.Int32
	release := make(chan struct{})
	p.dialProbe = func(_ context.Context, _ string, _ int, _ time.Duration) bool {
		calls.Add(1)
		<-release
		return true
	}

	ip := netip.MustParseAddr("1.1.1.1")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.probeIP(context.Background(), ip, 443)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("dial called %d times, want 1", n)
	}
}
