package ecs

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
)

func Test_isPublicAddr(t *testing.T) {
	tests := map[string]bool{
		"1.2.3.4":          true,
		"240e:3a1::1":      true,
		"::ffff:1.2.3.4":   true,
		"127.0.0.1":        false,
		"::1":              false,
		"10.42.0.5":        false,
		"172.17.0.1":       false,
		"192.168.1.10":     false,
		"169.254.1.1":      false,
		"fe80::1":          false,
		"fd00::1":          false,
		"100.64.0.1":       false,
		"198.18.0.1":       false,
		"0.0.0.0":          false,
		"::ffff:10.0.0.1":  false,
		"::ffff:127.0.0.1": false,
	}
	for s, want := range tests {
		if got := isPublicAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", s, got, want)
		}
	}
}

func Test_ecsPlugin_nonPublic(t *testing.T) {
	tests := []struct {
		name       string
		args       Args
		clientAddr string
		clientECS  string // ECS the query arrives with, "" for none
		wantECS    string // ECS sent on, "" for none
	}{
		{"public client", Args{Auto: true}, "1.2.3.4", "", "1.2.3.0/24"},
		{"loopback client: no ecs", Args{Auto: true}, "127.0.0.1", "", ""},
		{"docker gateway client: no ecs", Args{Auto: true}, "172.17.0.1", "", ""},
		{"ula client: no ecs", Args{Auto: true}, "fd00::1", "", ""},
		{"private ecs replaced by public client", Args{Auto: true}, "1.2.3.4", "192.168.1.0/24", "1.2.3.0/24"},
		{"private ecs dropped for private client", Args{Auto: true}, "127.0.0.1", "192.168.1.0/24", ""},
		{"private ecs dropped with force_overwrite", Args{Auto: true, ForceOverwrite: true}, "127.0.0.1", "10.0.0.0/24", ""},
		{"public ecs kept", Args{Auto: true}, "127.0.0.1", "5.6.7.0/24", "5.6.7.0/24"},
		{"opt-out /0 kept", Args{Auto: true}, "1.2.3.4", "0.0.0.0/0", "0.0.0.0/0"},
		{"private ecs dropped in preset mode", Args{IPv4: "5.6.7.8"}, "", "192.168.1.0/24", "5.6.7.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := newPlugin(coremain.NewBP("ecs", PluginType, nil, nil), &tt.args)
			if err != nil {
				t.Fatal(err)
			}

			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			if tt.clientECS != "" {
				pfx := netip.MustParsePrefix(tt.clientECS)
				dnsutils.AddECS(dnsutils.UpgradeEDNS0(q),
					dnsutils.NewEDNS0Subnet(pfx.Addr().AsSlice(), uint8(pfx.Bits()), pfx.Addr().Is6()), true)
			}
			// Round trip through the wire, as a real query arrives.
			wire, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			q = new(dns.Msg)
			if err := q.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			var addr netip.Addr
			if tt.clientAddr != "" {
				addr = netip.MustParseAddr(tt.clientAddr)
			}
			qCtx := C.NewContext(q, C.NewRequestMeta(addr))

			var sent string
			next := executable_seq.WrapExecutable(ecsRecorder{sent: &sent})
			if err := p.Exec(context.Background(), qCtx, next); err != nil {
				t.Fatal(err)
			}
			if sent != tt.wantECS {
				t.Fatalf("sent ecs %q, want %q", sent, tt.wantECS)
			}
		})
	}
}

// ecsRecorder records the ECS of the query it receives, masked to the
// source prefix as it goes on the wire.
type ecsRecorder struct {
	sent *string
}

func (r ecsRecorder) Exec(_ context.Context, qCtx *C.Context, _ executable_seq.ExecutableChainNode) error {
	if e := dnsutils.GetMsgECS(qCtx.Q()); e != nil {
		addr, _ := netip.AddrFromSlice(e.Address)
		pfx, _ := addr.Unmap().Prefix(int(e.SourceNetmask))
		*r.sent = fmt.Sprint(pfx)
	}
	resp := new(dns.Msg)
	resp.SetReply(qCtx.Q())
	qCtx.SetResponse(resp)
	return nil
}
