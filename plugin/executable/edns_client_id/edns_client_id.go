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

// Package edns_client_id implements reading/writing/stripping a private EDNS0
// option that carries a list of client identity tags. It is the second
// machine-to-machine identity channel (the first being the DoH URL path), so
// the tag set can travel over any transport (UDP/TCP/DoT/DoH).
package edns_client_id

import (
	"context"
	"fmt"
	"sort"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "edns_client_id"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*ednsClientID)(nil)

// Mode constants.
const (
	// ModeRead reads the option into RequestMeta.clientIDs and removes it from
	// the query (read and strip combined, to avoid leaking the tag set).
	ModeRead = "read"
	// ModeWrite writes RequestMeta.clientIDs into the option.
	ModeWrite = "write"
	// ModeStrip only removes the option from the query.
	ModeStrip = "strip"
)

const (
	// defaultOptionCode is in the private/experimental EDNS0 range
	// (65001-65534). 65001 is conventionally used for the dnsmasq/OpenWrt MAC.
	defaultOptionCode uint16 = 65002
	// maxTagLen is the maximum length of a single tag, limited by the 1-byte
	// length field of each TLV.
	maxTagLen = 255
	// maxOptionDataLen is the maximum total size of the option data.
	maxOptionDataLen = 512
	// defaultUDPSize is the EDNS0 UDP buffer size used when creating a new OPT.
	defaultUDPSize = 4096
)

type Args struct {
	// Mode is required and must be one of: read, write, strip.
	Mode string `yaml:"mode"`
	// OptionCode is the private EDNS0 option code. Defaults to 65002.
	OptionCode uint16 `yaml:"option_code"`
}

type ednsClientID struct {
	*coremain.BP
	mode       string
	optionCode uint16
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newEdnsClientID(bp, args.(*Args))
}

func newEdnsClientID(bp *coremain.BP, args *Args) (*ednsClientID, error) {
	switch args.Mode {
	case ModeRead, ModeWrite, ModeStrip:
	default:
		return nil, fmt.Errorf("edns_client_id: invalid mode %q, must be one of: read, write, strip", args.Mode)
	}

	code := args.OptionCode
	if code == 0 {
		code = defaultOptionCode
	}

	return &ednsClientID{
		BP:         bp,
		mode:       args.Mode,
		optionCode: code,
	}, nil
}

// Exec never blocks the query. It applies the configured mode to the query msg
// and always passes the context to the next node.
func (p *ednsClientID) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()

	switch p.mode {
	case ModeRead:
		p.read(qCtx, q)
	case ModeWrite:
		p.write(qCtx, q)
	case ModeStrip:
		stripOption(q, p.optionCode)
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

// read collects every option with the configured code, decodes the TLVs,
// merges them into RequestMeta.clientIDs (deduplicated), then removes all the
// options with that code from the query. Other EDNS0 options are preserved.
func (p *ednsClientID) read(qCtx *query_context.Context, q *dns.Msg) {
	opt := q.IsEdns0()
	if opt == nil {
		return
	}

	var tags []string
	for _, o := range opt.Option {
		if o.Option() != p.optionCode {
			continue
		}
		local, ok := o.(*dns.EDNS0_LOCAL)
		if !ok {
			continue
		}
		decoded, malformed := decodeOptionData(local.Data)
		tags = append(tags, decoded...)
		if malformed {
			p.L().Warn("edns_client_id: malformed option data, stopped parsing",
				zap.Uint16("option_code", p.optionCode),
			)
		}
	}

	// Always strip our own option, even if it held no usable tags.
	opt.Option = removeOptionCode(opt.Option, p.optionCode)

	if len(tags) == 0 {
		return
	}
	meta := qCtx.ReqMeta()
	meta.SetClientIDs(mergeTags(meta.GetClientIDs(), tags))
}

// write encodes RequestMeta.clientIDs (sorted and deduplicated) into the option.
// An existing option with the same code is replaced. If there are no IDs, the
// query is left untouched.
func (p *ednsClientID) write(qCtx *query_context.Context, q *dns.Msg) {
	ids := qCtx.ReqMeta().GetClientIDs()
	if len(ids) == 0 {
		return
	}

	data, dropped := encodeOptionData(ids)
	if dropped > 0 {
		p.L().Warn("edns_client_id: dropped tags that do not fit the option size limit",
			zap.Uint16("option_code", p.optionCode),
			zap.Int("dropped", dropped),
			zap.Int("option_data_len", len(data)),
		)
	}
	if len(data) == 0 {
		return
	}

	opt := q.IsEdns0()
	if opt == nil {
		q.SetEdns0(defaultUDPSize, false)
		opt = q.IsEdns0()
		if opt == nil { // unreachable, SetEdns0 always appends an OPT
			return
		}
	}

	// Replace existing same-code options to avoid duplicates.
	opt.Option = removeOptionCode(opt.Option, p.optionCode)
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: p.optionCode, Data: data})
}

// stripOption removes every EDNS0 option with the given code from q, leaving
// other options intact. It does not touch RequestMeta.
func stripOption(q *dns.Msg, code uint16) {
	opt := q.IsEdns0()
	if opt == nil {
		return
	}
	opt.Option = removeOptionCode(opt.Option, code)
}

// removeOptionCode returns a new slice containing every option whose code is
// not code, preserving the order and identity of the other options.
func removeOptionCode(opts []dns.EDNS0, code uint16) []dns.EDNS0 {
	out := make([]dns.EDNS0, 0, len(opts))
	for _, o := range opts {
		if o.Option() != code {
			out = append(out, o)
		}
	}
	return out
}

// mergeTags returns the deduplicated, sorted union of existing and incoming
// tags. Empty tags are ignored.
func mergeTags(existing, incoming []string) []string {
	merged := make([]string, 0, len(existing)+len(incoming))
	merged = append(merged, existing...)
	merged = append(merged, incoming...)
	return sortDedupTags(merged)
}

// sortDedupTags returns tags sorted in ascending order with duplicates and
// empty strings removed.
func sortDedupTags(tags []string) []string {
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// encodeOptionData encodes tags as a TLV list: repeated
// [1-byte length][tag bytes]. Tags are sorted and deduplicated first. Tags
// longer than maxTagLen or that would exceed maxOptionDataLen are dropped; the
// returned int is the number of dropped tags.
func encodeOptionData(tags []string) (data []byte, dropped int) {
	uniq := sortDedupTags(tags)
	data = make([]byte, 0, len(uniq)*8)
	for _, t := range uniq {
		if len(t) > maxTagLen || len(data)+1+len(t) > maxOptionDataLen {
			dropped++
			continue
		}
		data = append(data, byte(len(t)))
		data = append(data, t...)
	}
	return data, dropped
}

// decodeOptionData parses a TLV list. It returns the tags decoded before the
// first malformed entry, and whether a malformed entry (length out of bounds /
// truncated) was encountered. It never panics.
func decodeOptionData(data []byte) (tags []string, malformed bool) {
	for i := 0; i < len(data); {
		l := int(data[i])
		i++
		if i+l > len(data) {
			return tags, true
		}
		tags = append(tags, string(data[i:i+l]))
		i += l
	}
	return tags, false
}
