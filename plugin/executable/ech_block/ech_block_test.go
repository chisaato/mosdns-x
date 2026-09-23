package ech_block

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	dnsproxy_upstream "github.com/AdguardTeam/dnsproxy/upstream"

	"github.com/pmkol/mosdns-x/coremain"
)

var _ dnsproxy_upstream.Upstream = (*fakeUpstream)(nil)

// fakeUpstream 按查询类型分派假响应，用于探测逻辑的单元测试
type fakeUpstream struct {
	mu      sync.Mutex
	handled []uint16

	// respByQtype 返回该 qtype 对应的答案记录；answer 为 nil 时表示空答案
	respByQtype map[uint16][]dns.RR
	// errByQtype 使该 qtype 的查询返回错误（模拟探测失败）
	errByQtype map[uint16]error
}

func (f *fakeUpstream) Exchange(m *dns.Msg) (*dns.Msg, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	qtype := m.Question[0].Qtype
	f.handled = append(f.handled, qtype)

	if err := f.errByQtype[qtype]; err != nil {
		return nil, err
	}

	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, f.respByQtype[qtype]...)
	return r, nil
}

func (f *fakeUpstream) Address() string { return "fake" }
func (f *fakeUpstream) Close() error    { return nil }

func (f *fakeUpstream) queryTypes() []uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint16(nil), f.handled...)
}

func aRR(name string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1"),
	}
}

func aaaaRR(name string) dns.RR {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2001:db8::1"),
	}
}

func newTestEchBlock(up dnsproxy_upstream.Upstream) *echBlock {
	return &echBlock{
		BP:           coremain.NewBP("test", PluginType, zap.NewNop(), nil),
		probeUp:      up,
		probeTimeout: time.Second,
		args:         &Args{CacheTTL: 30},
	}
}

func TestProbeDualFamily(t *testing.T) {
	qName := "example.com."

	tests := []struct {
		name        string
		respByQtype map[uint16][]dns.RR
		errByQtype  map[uint16]error
		wantBlocked bool
	}{
		{
			name: "a record only, blocked",
			respByQtype: map[uint16][]dns.RR{
				dns.TypeA: {aRR(qName)},
			},
			wantBlocked: true,
		},
		{
			name: "aaaa record only, blocked",
			respByQtype: map[uint16][]dns.RR{
				dns.TypeAAAA: {aaaaRR(qName)},
			},
			wantBlocked: true,
		},
		{
			name:        "both families empty, pass through",
			respByQtype: map[uint16][]dns.RR{},
			wantBlocked: false,
		},
		{
			name:        "probe exchange failed, pass through",
			errByQtype:  map[uint16]error{dns.TypeA: errors.New("connection refused")},
			wantBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &fakeUpstream{
				respByQtype: tt.respByQtype,
				errByQtype:  tt.errByQtype,
			}
			b := newTestEchBlock(up)

			blocked, err := b.probe(qName)
			if tt.wantBlocked {
				if err != nil {
					t.Fatalf("probe() error = %v, want nil", err)
				}
				if !blocked {
					t.Fatalf("probe() blocked = false, want true")
				}
			} else {
				if tt.errByQtype != nil && err == nil {
					t.Fatalf("probe() error = nil, want non-nil")
				}
				if blocked {
					t.Fatalf("probe() blocked = true, want false")
				}
			}

			// 确认两个族都被探测到（A 与 AAAA 各一次）
			got := up.queryTypes()
			seen := make(map[uint16]int)
			for _, qt := range got {
				seen[qt]++
			}
			if seen[dns.TypeA] != 1 || seen[dns.TypeAAAA] != 1 {
				t.Fatalf("probe() sent queries %v, want one A and one AAAA", got)
			}
		})
	}
}
