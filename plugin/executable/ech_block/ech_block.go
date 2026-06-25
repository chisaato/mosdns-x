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

package ech_block

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	dnsproxy_upstream "github.com/AdguardTeam/dnsproxy/upstream"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/matcher/msg_matcher"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "ech_block"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*echBlock)(nil)

type Args struct {
	ProbeDNS      string   `yaml:"probe_dns"`
	ProbeTimeout  int      `yaml:"probe_timeout"`
	BlockMode     string   `yaml:"block_mode"`
	AllowDomains  []string `yaml:"allow_domains"`
	CacheSize     int      `yaml:"cache_size"`
	CacheTTL      int      `yaml:"cache_ttl"`
}

type probeCacheEntry struct {
	blocked  bool
	expireAt time.Time
}

type echBlock struct {
	*coremain.BP
	args    *Args
	probeUp dnsproxy_upstream.Upstream

	allowMatcher executable_seq.Matcher
	closer       io.Closer

	cache *concurrent_lru.ConcurrentLRU[string, *probeCacheEntry]
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newEchBlock(bp, args.(*Args))
}

func newEchBlock(bp *coremain.BP, args *Args) (*echBlock, error) {
	if len(args.ProbeDNS) == 0 {
		return nil, fmt.Errorf("probe_dns is required")
	}

	switch args.BlockMode {
	case "", "refused", "nxdomain", "empty":
	default:
		return nil, fmt.Errorf("unsupported block_mode: %s", args.BlockMode)
	}
	if args.BlockMode == "" {
		args.BlockMode = "refused"
	}

	timeout := time.Duration(args.ProbeTimeout) * time.Millisecond
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}

	cacheSize := args.CacheSize
	if cacheSize <= 0 {
		cacheSize = 10000
	}
	if args.CacheTTL <= 0 {
		args.CacheTTL = 30
	}

	probeAddr := args.ProbeDNS
	if _, _, err := net.SplitHostPort(probeAddr); err != nil {
		probeAddr = net.JoinHostPort(probeAddr, "53")
	}

	probeUp, err := dnsproxy_upstream.AddressToUpstream(probeAddr, &dnsproxy_upstream.Options{
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init probe upstream: %w", err)
	}

	b := &echBlock{
		BP:      bp,
		args:    args,
		probeUp: probeUp,
		cache: concurrent_lru.NewConecurrentLRU[string, *probeCacheEntry](cacheSize, nil),
	}

	if len(args.AllowDomains) > 0 {
		dm, err := domain.BatchLoadDomainProvider(args.AllowDomains, bp.M().GetDataManager())
		if err != nil {
			probeUp.Close()
			return nil, fmt.Errorf("failed to load allow_domains: %w", err)
		}
		b.allowMatcher = msg_matcher.NewQNameMatcher(dm)
		b.closer = dm
		bp.L().Info("ech_block: allow domains loaded", zap.Int("count", dm.Len()))
	}

	return b, nil
}

func (b *echBlock) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if len(q.Question) != 1 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	if q.Question[0].Qtype != dns.TypeHTTPS {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	qName := q.Question[0].Name

	if b.allowMatcher != nil {
		allowed, err := b.allowMatcher.Match(ctx, qCtx)
		if err != nil {
			b.L().Warn("allow domain match error", zap.Error(err))
		} else if allowed {
			b.L().Debug("domain in allow list, pass through", zap.String("qname", qName))
			return executable_seq.ExecChainNode(ctx, qCtx, next)
		}
	}

	blocked, err := b.lookup(qName)
	if err != nil {
		b.L().Warn("probe failed, pass through",
			zap.String("qname", qName),
			zap.String("probe_dns", b.args.ProbeDNS),
			zap.Error(err),
		)
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	if !blocked {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	b.L().Info("blocked TYPE65",
		zap.String("qname", qName),
		zap.String("probe_dns", b.args.ProbeDNS),
	)
	b.block(qCtx)
	return nil
}

func (b *echBlock) lookup(qName string) (bool, error) {
	now := time.Now()

	if entry, ok := b.cache.Get(qName); ok && now.Before(entry.expireAt) {
		return entry.blocked, nil
	}

	blocked, err := b.probe(qName)
	if err != nil {
		return false, err
	}

	b.cache.Add(qName, &probeCacheEntry{
		blocked:  blocked,
		expireAt: now.Add(time.Duration(b.args.CacheTTL) * time.Second),
	})
	return blocked, nil
}

func (b *echBlock) probe(qName string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(qName, dns.TypeA)
	m.SetEdns0(1232, false)

	r, err := b.probeUp.Exchange(m)
	if err != nil {
		return false, fmt.Errorf("probe exchange: %w", err)
	}
	if r == nil {
		return false, nil
	}

	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			return true, nil
		}
	}
	return false, nil
}

func (b *echBlock) block(qCtx *query_context.Context) {
	q := qCtx.Q()

	switch b.args.BlockMode {
	case "refused":
		r := dnsutils.GenEmptyReply(q, dns.RcodeRefused)
		qCtx.SetResponse(r)
	case "nxdomain":
		r := dnsutils.GenEmptyReply(q, dns.RcodeNameError)
		qCtx.SetResponse(r)
	case "empty":
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeSuccess)
		r.RecursionAvailable = true
		qCtx.SetResponse(r)
	default:
		r := dnsutils.GenEmptyReply(q, dns.RcodeRefused)
		qCtx.SetResponse(r)
	}
}

func (b *echBlock) Close() error {
	b.probeUp.Close()
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}
