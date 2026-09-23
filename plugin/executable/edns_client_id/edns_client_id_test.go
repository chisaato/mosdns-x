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

package edns_client_id

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const testCode uint16 = 65002

func netipZero() netip.Addr {
	return netip.Addr{}
}

func newTestPlugin(t *testing.T, args *Args) *ednsClientID {
	t.Helper()
	p, err := newEdnsClientID(coremain.NewBP("test", PluginType, zap.NewNop(), nil), args)
	if err != nil {
		t.Fatalf("newEdnsClientID() error = %v", err)
	}
	return p
}

func newQuery() *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	return q
}

func addLocalOption(q *dns.Msg, code uint16, data []byte) {
	opt := q.IsEdns0()
	if opt == nil {
		q.SetEdns0(4096, false)
		opt = q.IsEdns0()
	}
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: code, Data: data})
}

func addSubnetOption(q *dns.Msg) {
	opt := q.IsEdns0()
	if opt == nil {
		q.SetEdns0(4096, false)
		opt = q.IsEdns0()
	}
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("1.2.3.0").To4(),
	})
}

func countOptions(q *dns.Msg, code uint16) int {
	opt := q.IsEdns0()
	if opt == nil {
		return 0
	}
	n := 0
	for _, o := range opt.Option {
		if o.Option() == code {
			n++
		}
	}
	return n
}

func hasSubnetOption(q *dns.Msg) bool {
	opt := q.IsEdns0()
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); ok {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Run("single tag", func(t *testing.T) {
		data, dropped := encodeOptionData([]string{"a"})
		if dropped != 0 {
			t.Fatalf("dropped = %d, want 0", dropped)
		}
		if want := []byte{1, 'a'}; !equalBytes(data, want) {
			t.Fatalf("data = %v, want %v", data, want)
		}
		tags, malformed := decodeOptionData(data)
		if malformed || !equalStrings(tags, []string{"a"}) {
			t.Fatalf("decode = %v malformed=%v", tags, malformed)
		}
	})

	t.Run("multiple tags sorted and deduped", func(t *testing.T) {
		data, dropped := encodeOptionData([]string{"b", "a", "b", "c"})
		if dropped != 0 {
			t.Fatalf("dropped = %d, want 0", dropped)
		}
		tags, malformed := decodeOptionData(data)
		if malformed {
			t.Fatal("unexpected malformed")
		}
		if want := []string{"a", "b", "c"}; !equalStrings(tags, want) {
			t.Fatalf("tags = %v, want %v", tags, want)
		}
	})

	t.Run("max length tag", func(t *testing.T) {
		long := strings.Repeat("x", maxTagLen)
		data, dropped := encodeOptionData([]string{long})
		if dropped != 0 {
			t.Fatalf("dropped = %d, want 0", dropped)
		}
		if len(data) != 1+maxTagLen {
			t.Fatalf("data len = %d, want %d", len(data), 1+maxTagLen)
		}
		tags, malformed := decodeOptionData(data)
		if malformed || len(tags) != 1 || tags[0] != long {
			t.Fatalf("round trip failed: len=%d malformed=%v", len(tags), malformed)
		}
	})

	t.Run("too long tag dropped", func(t *testing.T) {
		tooLong := strings.Repeat("x", maxTagLen+1)
		data, dropped := encodeOptionData([]string{tooLong, "ok"})
		if dropped != 1 {
			t.Fatalf("dropped = %d, want 1", dropped)
		}
		tags, _ := decodeOptionData(data)
		if !equalStrings(tags, []string{"ok"}) {
			t.Fatalf("tags = %v, want [ok]", tags)
		}
	})

	t.Run("total size limit drops overflow", func(t *testing.T) {
		// Each tag takes 1+100 bytes; 6 of them overflow the 512-byte cap.
		var tags []string
		for i := 0; i < 6; i++ {
			tags = append(tags, strings.Repeat(string(rune('a'+i)), 100))
		}
		data, dropped := encodeOptionData(tags)
		if dropped == 0 {
			t.Fatal("expected some tags to be dropped")
		}
		if len(data) > maxOptionDataLen {
			t.Fatalf("data len = %d, exceeds cap %d", len(data), maxOptionDataLen)
		}
	})
}

func TestDecodeMalformed(t *testing.T) {
	// A valid TLV followed by a length byte that points past the end.
	data := append([]byte{2, 'o', 'k'}, 10)
	tags, malformed := decodeOptionData(data)
	if !malformed {
		t.Fatal("expected malformed=true")
	}
	if !equalStrings(tags, []string{"ok"}) {
		t.Fatalf("partial tags = %v, want [ok]", tags)
	}

	// A lone length byte is malformed too, and must not panic.
	if _, malformed := decodeOptionData([]byte{3}); !malformed {
		t.Fatal("expected malformed for truncated length")
	}
}

func TestReadMode(t *testing.T) {
	p := newTestPlugin(t, &Args{Mode: ModeRead})

	q := newQuery()
	addSubnetOption(q)
	addLocalOption(q, testCode, mustEncode([]string{"accel", "intl"}))
	addLocalOption(q, 65123, []byte{1, 'x'}) // another private option must survive

	meta := query_context.NewRequestMeta(netipZero())
	meta.SetClientIDs([]string{"existing"})
	qCtx := query_context.NewContext(q, meta)

	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}

	// Union of existing + decoded, deduped and sorted.
	if got, want := meta.GetClientIDs(), []string{"accel", "existing", "intl"}; !equalStrings(got, want) {
		t.Fatalf("clientIDs = %v, want %v", got, want)
	}

	// Our option is stripped; the others are preserved.
	if n := countOptions(q, testCode); n != 0 {
		t.Fatalf("our option count = %d, want 0", n)
	}
	if n := countOptions(q, 65123); n != 1 {
		t.Fatalf("other local option count = %d, want 1", n)
	}
	if !hasSubnetOption(q) {
		t.Fatal("subnet option was not preserved")
	}
}

func TestReadModeMalformedDoesNotFail(t *testing.T) {
	p := newTestPlugin(t, &Args{Mode: ModeRead})

	q := newQuery()
	// valid "ok" TLV then a truncated one
	data := append(mustEncode([]string{"ok"}), 10)
	addLocalOption(q, testCode, data)

	meta := query_context.NewRequestMeta(netipZero())
	qCtx := query_context.NewContext(q, meta)

	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatalf("Exec() must not fail on malformed data, got %v", err)
	}
	if got, want := meta.GetClientIDs(), []string{"ok"}; !equalStrings(got, want) {
		t.Fatalf("clientIDs = %v, want %v", got, want)
	}
	if n := countOptions(q, testCode); n != 0 {
		t.Fatalf("our option count = %d, want 0", n)
	}
}

func TestReadModeNoOPT(t *testing.T) {
	p := newTestPlugin(t, &Args{Mode: ModeRead})

	q := newQuery()
	meta := query_context.NewRequestMeta(netipZero())
	meta.SetClientIDs([]string{"keep"})
	qCtx := query_context.NewContext(q, meta)

	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if got, want := meta.GetClientIDs(), []string{"keep"}; !equalStrings(got, want) {
		t.Fatalf("clientIDs = %v, want %v", got, want)
	}
	if q.IsEdns0() != nil {
		t.Fatal("query should not gain an OPT")
	}
}

func TestWriteMode(t *testing.T) {
	p := newTestPlugin(t, &Args{Mode: ModeWrite})

	t.Run("writes sorted deduped and replaces existing", func(t *testing.T) {
		q := newQuery()
		addSubnetOption(q)
		addLocalOption(q, testCode, mustEncode([]string{"stale"})) // old option to replace

		meta := query_context.NewRequestMeta(netipZero())
		meta.SetClientIDs([]string{"b", "a", "b"})
		qCtx := query_context.NewContext(q, meta)

		if err := p.Exec(context.Background(), qCtx, nil); err != nil {
			t.Fatalf("Exec() error = %v", err)
		}

		if n := countOptions(q, testCode); n != 1 {
			t.Fatalf("our option count = %d, want 1 (replaced, not duplicated)", n)
		}
		var got []string
		opt := q.IsEdns0()
		for _, o := range opt.Option {
			if o.Option() == testCode {
				local := o.(*dns.EDNS0_LOCAL)
				got, _ = decodeOptionData(local.Data)
			}
		}
		if want := []string{"a", "b"}; !equalStrings(got, want) {
			t.Fatalf("written tags = %v, want %v", got, want)
		}
		if !hasSubnetOption(q) {
			t.Fatal("subnet option was not preserved")
		}
	})

	t.Run("creates OPT when absent", func(t *testing.T) {
		q := newQuery()
		meta := query_context.NewRequestMeta(netipZero())
		meta.SetClientIDs([]string{"accel"})
		qCtx := query_context.NewContext(q, meta)

		if err := p.Exec(context.Background(), qCtx, nil); err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
		if q.IsEdns0() == nil {
			t.Fatal("OPT should have been created")
		}
		if n := countOptions(q, testCode); n != 1 {
			t.Fatalf("option count = %d, want 1", n)
		}
	})

	t.Run("empty ids leaves message untouched", func(t *testing.T) {
		q := newQuery()
		extraBefore := len(q.Extra)
		meta := query_context.NewRequestMeta(netipZero())
		qCtx := query_context.NewContext(q, meta)

		if err := p.Exec(context.Background(), qCtx, nil); err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
		if len(q.Extra) != extraBefore || q.IsEdns0() != nil {
			t.Fatal("query should not be modified when there are no ids")
		}
	})
}

func TestStripMode(t *testing.T) {
	p := newTestPlugin(t, &Args{Mode: ModeStrip})

	q := newQuery()
	addSubnetOption(q)
	addLocalOption(q, testCode, mustEncode([]string{"secret"}))
	addLocalOption(q, 65123, []byte{1, 'x'})

	meta := query_context.NewRequestMeta(netipZero())
	meta.SetClientIDs([]string{"keep"})
	qCtx := query_context.NewContext(q, meta)

	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}

	if n := countOptions(q, testCode); n != 0 {
		t.Fatalf("our option count = %d, want 0", n)
	}
	if n := countOptions(q, 65123); n != 1 {
		t.Fatalf("other local option count = %d, want 1", n)
	}
	if !hasSubnetOption(q) {
		t.Fatal("subnet option was not preserved")
	}
	if got, want := meta.GetClientIDs(), []string{"keep"}; !equalStrings(got, want) {
		t.Fatalf("meta must not be modified by strip; got %v want %v", got, want)
	}
}

func TestInitValidation(t *testing.T) {
	bp := coremain.NewBP("test", PluginType, zap.NewNop(), nil)

	for _, mode := range []string{ModeRead, ModeWrite, ModeStrip} {
		p, err := newEdnsClientID(bp, &Args{Mode: mode})
		if err != nil {
			t.Fatalf("mode %q should be valid, got %v", mode, err)
		}
		if p.optionCode != defaultOptionCode {
			t.Fatalf("default option code = %d, want %d", p.optionCode, defaultOptionCode)
		}
	}

	for _, mode := range []string{"", "READ", "invalid"} {
		if _, err := newEdnsClientID(bp, &Args{Mode: mode}); err == nil {
			t.Fatalf("mode %q should be rejected", mode)
		}
	}

	p, err := newEdnsClientID(bp, &Args{Mode: ModeRead, OptionCode: 60000})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.optionCode != 60000 {
		t.Fatalf("option code = %d, want 60000", p.optionCode)
	}
}

func mustEncode(tags []string) []byte {
	data, _ := encodeOptionData(tags)
	return data
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
