package responsematcher

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

func TestHasNoError(t *testing.T) {
	e := &hasNoError{BP: coremain.NewBP("test", "_response_noerror", nil, nil)}

	newQCtx := func(r *dns.Msg) *query_context.Context {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		qCtx := query_context.NewContext(q, nil)
		if r != nil {
			qCtx.SetResponse(r)
		}
		return qCtx
	}

	noErrorEmpty := func() *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeSuccess)
		return r
	}

	noErrorWithAnswer := func() *dns.Msg {
		r := noErrorEmpty()
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{192, 0, 2, 1},
		})
		return r
	}

	nxDomain := func() *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeNameError)
		return r
	}

	tests := []struct {
		name        string
		response    *dns.Msg
		wantMatched bool
	}{
		{name: "noerror with empty answer", response: noErrorEmpty(), wantMatched: true},
		{name: "noerror with answer", response: noErrorWithAnswer(), wantMatched: true},
		{name: "nxdomain", response: nxDomain(), wantMatched: false},
		{name: "no response", response: nil, wantMatched: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := e.Match(context.Background(), newQCtx(tt.response))
			if err != nil {
				t.Fatalf("Match() error = %v, want nil", err)
			}
			if matched != tt.wantMatched {
				t.Fatalf("Match() matched = %v, want %v", matched, tt.wantMatched)
			}
		})
	}
}
