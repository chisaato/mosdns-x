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
	"strconv"
	"strings"
	"sync"
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
	ProbeDNS                string   `yaml:"probe_dns"`
	ProbeTimeout            int      `yaml:"probe_timeout"`
	ProbeBootstrap          []string `yaml:"probe_bootstrap"`
	ProbeInsecureSkipVerify bool     `yaml:"probe_insecure_skip_verify"`
	BlockMode               string   `yaml:"block_mode"`
	AllowDomains            []string `yaml:"allow_domains"`
	CacheSize               int      `yaml:"cache_size"`
	CacheTTL                int      `yaml:"cache_ttl"`
	// MaxPassTTL caps the ttl of a TYPE65 response that passed the probe
	// (not blocked, or probe failed). 0 means CacheTTL, < 0 disables it.
	MaxPassTTL int `yaml:"max_pass_ttl"`
}

type probeCacheEntry struct {
	blocked  bool
	expireAt time.Time
}

type echBlock struct {
	*coremain.BP
	args         *Args
	probeUp      dnsproxy_upstream.Upstream
	probeTimeout time.Duration

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
		args.BlockMode = "empty"
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
	if args.MaxPassTTL == 0 {
		args.MaxPassTTL = args.CacheTTL
	}

	probeAddr := args.ProbeDNS
	switch {
	case strings.Contains(probeAddr, "://"):
	default:
		if _, _, err := net.SplitHostPort(probeAddr); err != nil {
			probeAddr = net.JoinHostPort(probeAddr, "53")
		}
	}

	opts := &dnsproxy_upstream.Options{
		Timeout:            timeout,
		InsecureSkipVerify: args.ProbeInsecureSkipVerify,
	}

	if len(args.ProbeBootstrap) > 0 {
		bsOpts := &dnsproxy_upstream.Options{
			Timeout: timeout,
		}
		if len(args.ProbeBootstrap) == 1 {
			r, err := dnsproxy_upstream.NewUpstreamResolver(args.ProbeBootstrap[0], bsOpts)
			if err != nil {
				return nil, fmt.Errorf("failed to create bootstrap resolver %s: %w", args.ProbeBootstrap[0], err)
			}
			opts.Bootstrap = dnsproxy_upstream.NewCachingResolver(r)
		} else {
			var resolvers []dnsproxy_upstream.Resolver
			for _, bs := range args.ProbeBootstrap {
				r, err := dnsproxy_upstream.NewUpstreamResolver(bs, bsOpts)
				if err != nil {
					return nil, fmt.Errorf("failed to create bootstrap resolver %s: %w", bs, err)
				}
				resolvers = append(resolvers, r)
			}
			pr := dnsproxy_upstream.ParallelResolver(resolvers)
			opts.Bootstrap = &pr
		}
	}

	probeUp, err := dnsproxy_upstream.AddressToUpstream(probeAddr, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to init probe upstream: %w", err)
	}

	b := &echBlock{
		BP:           bp,
		args:         args,
		probeUp:      probeUp,
		probeTimeout: timeout,
		cache:        concurrent_lru.NewConecurrentLRU[string, *probeCacheEntry](cacheSize, nil),
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
		b.L().Warn(
			"probe failed, pass through",
			zap.String("qname", qName),
			zap.String("probe_dns", b.args.ProbeDNS),
			zap.Error(err),
		)
		return b.passThrough(ctx, qCtx, next)
	}

	if !blocked {
		return b.passThrough(ctx, qCtx, next)
	}

	b.L().Info(
		"blocked TYPE65",
		zap.String("qname", qName),
		zap.String("probe_dns", b.args.ProbeDNS),
	)
	b.block(qCtx)
	return nil
}

// passThrough hands a probed TYPE65 query over to the next node and caps the
// ttl of the response at MaxPassTTL.
//
// The pass verdict only holds until the probe is redone, so the upstream
// HTTPS record (possibly carrying ECH) must not outlive it. Otherwise, once
// the domain gets hijacked, the client could keep the ECH config cached next
// to the fresh hijacked A/AAAA record and fail the handshake.
func (b *echBlock) passThrough(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if r := qCtx.R(); r != nil && b.args.MaxPassTTL > 0 {
		dnsutils.ApplyMaximumTTL(r, uint32(b.args.MaxPassTTL))
	}
	return err
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

	b.cache.Add(
		qName, &probeCacheEntry{
			blocked:  blocked,
			expireAt: now.Add(time.Duration(b.args.CacheTTL) * time.Second),
		},
	)
	return blocked, nil
}

// probe 对 probe_dns 并发发起 A 与 AAAA 查询，
// 任一族答案非空即视为该域名已接管（blocked）。
// 两族查询共享同一超时预算，任一族失败且无 blocked 证据时返回错误（放行）。
func (b *echBlock) probe(qName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.probeTimeout)
	defer cancel()

	type probeResult struct {
		blocked bool
		err     error
	}

	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	resultCh := make(chan probeResult, len(qtypes))

	var wg sync.WaitGroup
	wg.Add(len(qtypes))
	for _, qtype := range qtypes {
		go func(qtype uint16) {
			defer wg.Done()

			m := new(dns.Msg)
			m.SetQuestion(qName, qtype)
			m.SetEdns0(1232, false)

			r, err := b.probeUp.Exchange(m)
			if err != nil {
				qtypeStr, ok := dns.TypeToString[qtype]
				if !ok {
					qtypeStr = strconv.FormatUint(uint64(qtype), 10)
				}
				resultCh <- probeResult{err: fmt.Errorf("probe exchange %s: %w", qtypeStr, err)}
				return
			}
			if r == nil {
				resultCh <- probeResult{}
				return
			}
			for _, rr := range r.Answer {
				if rr.Header().Rrtype == qtype {
					resultCh <- probeResult{blocked: true}
					return
				}
			}
			resultCh <- probeResult{}
		}(qtype)
	}

	// 共享超时控制：等待两族探测全部完成，或整体超时后提前放行
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var blocked bool
	var firstErr error
	select {
	case <-done:
		for range qtypes {
			res := <-resultCh
			if res.blocked {
				blocked = true
			}
			if res.err != nil && firstErr == nil {
				firstErr = res.err
			}
		}
	case <-ctx.Done():
		return false, fmt.Errorf("probe timeout after %s", b.probeTimeout)
	}

	// 有确凿的 blocked 证据时优先阻断，否则按失败放行处理
	if blocked {
		return true, nil
	}
	if firstErr != nil {
		return false, firstErr
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
		// 这才是安全的阻断 HTTPS/TYPE65 的方式
		// 也就是用空响应和 RCODE=0 进行返回
		// 不能用 nxdomain
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeSuccess)
		r.RecursionAvailable = true
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
