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
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/AdguardTeam/dnsproxy/fastip"
	dnsproxy_upstream "github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"go.uber.org/zap"
)

const PluginType = "adg_forward"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*adgForward)(nil)

// UpstreamMode 对应 AdGuard 上游模式，与 dnsproxy/proxy.UpstreamMode 一致。
type UpstreamMode string

const (
	ModeLoadBalance UpstreamMode = "load_balance" // 默认，加权随机
	ModeParallel    UpstreamMode = "parallel"     // 并发请求，返回最先成功的
	ModeFastestAddr UpstreamMode = "fastest_addr" // 最快 IP（查询全部上游 → ping → 返回最快 IP）
)

type Args struct {
	// 上游地址列表。
	Upstream []UpstreamConfig `yaml:"upstream"`

	// 全局 bootstrap pool。所有上游共享，做并发域名解析。
	// 每个地址必须是纯 IP，支持任意协议。
	Bootstrap []string `yaml:"bootstrap"`

	// 上游模式，默认 load_balance。
	Mode UpstreamMode `yaml:"mode"`

	// 全局超时（秒），默认 5。
	Timeout int `yaml:"timeout"`

	// 出站 URL 透传客户端 client_id：把 ReqMeta 中的 clientIDs 以 path 段
	// 形式追加到每个 upstream addr 的路径后（/dns-query + "/" + ids...）。
	ClientIDPassthrough bool `yaml:"client_id_passthrough"`
	// 每个"不同 client_id 集合"懒构建一组变体 upstream，用 LRU 缓存。
	PassthroughCacheSize int `yaml:"passthrough_cache_size"` // 默认 16
}

type UpstreamConfig struct {
	Addr               string `yaml:"addr"`  // required
	HTTP3              bool   `yaml:"http3"` // enable HTTP/3
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	Trusted            bool   `yaml:"trusted"` // 未配置时第一个 upstream 强制 trusted
}

type rttStats struct {
	mu     sync.Mutex
	rttSum float64 // 微秒累计
	reqNum float64
}

func (s *rttStats) update(rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rttSum += float64(rtt.Microseconds())
	s.reqNum++
}

func (s *rttStats) weight() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rttSum == 0 || s.reqNum == 0 {
		return 1
	}
	return 1 / (s.rttSum / s.reqNum)
}

type adgForward struct {
	*coremain.BP
	args *Args
	mode UpstreamMode

	// dnsproxy 原生 upstream 列表。
	rawUpstreams    []dnsproxy_upstream.Upstream
	upstreamsCloser []dnsproxy_upstream.Upstream

	// 构建 upstream 所用的共享参数（供 base 与 client_id 变体复用）。
	timeout   time.Duration
	bootstrap dnsproxy_upstream.Resolver

	// client_id 出站透传：按 client_id 集合懒构建变体 upstream。
	passthroughCache *concurrent_lru.ConcurrentLRU[string, []dnsproxy_upstream.Upstream]
	passthroughMu    sync.Mutex

	// fastest_addr 模式
	fastestAddr *fastip.FastestAddr

	// load_balance 模式
	rttLock     sync.Mutex
	rttStatsMap map[string]*rttStats
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newAdgForward(bp, args.(*Args))
}

func newAdgForward(bp *coremain.BP, args *Args) (*adgForward, error) {
	if len(args.Upstream) == 0 {
		return nil, errors.New("no upstream is configured")
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// 校验 mode
	switch args.Mode {
	case "", ModeLoadBalance:
		args.Mode = ModeLoadBalance
	case ModeParallel, ModeFastestAddr:
	default:
		return nil, fmt.Errorf("unknown upstream mode %q, supported: load_balance, parallel, fastest_addr", args.Mode)
	}

	f := &adgForward{
		BP:      bp,
		args:    args,
		mode:    args.Mode,
		timeout: timeout,
	}

	if args.Mode == ModeFastestAddr {
		f.fastestAddr = fastip.New(&fastip.Config{})
	}

	if args.Mode == ModeLoadBalance {
		f.rttStatsMap = make(map[string]*rttStats)
	}

	// client_id 出站透传的变体缓存；逐出时关闭对应 upstream 释放连接池。
	if args.ClientIDPassthrough {
		cacheSize := args.PassthroughCacheSize
		if cacheSize <= 0 {
			cacheSize = defaultPassthroughCacheSize
		}
		f.passthroughCache = concurrent_lru.NewConecurrentLRU[string, []dnsproxy_upstream.Upstream](
			cacheSize,
			func(_ string, ups []dnsproxy_upstream.Upstream) {
				closeUpstreamGroup(ups)
			},
		)
	}

	// ── Build global bootstrap pool ──────────────────────────────────────
	if len(args.Bootstrap) > 0 {
		bsOpts := &dnsproxy_upstream.Options{
			Timeout: timeout,
		}

		if len(args.Bootstrap) == 1 {
			r, err := dnsproxy_upstream.NewUpstreamResolver(args.Bootstrap[0], bsOpts)
			if err != nil {
				return nil, fmt.Errorf("failed to create bootstrap resolver %s: %w", args.Bootstrap[0], err)
			}
			f.bootstrap = dnsproxy_upstream.NewCachingResolver(r)
		} else {
			var resolvers []dnsproxy_upstream.Resolver
			for _, bs := range args.Bootstrap {
				r, err := dnsproxy_upstream.NewUpstreamResolver(bs, bsOpts)
				if err != nil {
					return nil, fmt.Errorf("failed to create bootstrap resolver %s: %w", bs, err)
				}
				resolvers = append(resolvers, r)
			}
			pr := dnsproxy_upstream.ParallelResolver(resolvers)
			f.bootstrap = &pr
		}
	}

	// ── Build each upstream ──────────────────────────────────────────────
	addrs := make([]string, 0, len(args.Upstream))
	for _, c := range args.Upstream {
		if len(c.Addr) == 0 {
			return nil, errors.New("missing upstream addr")
		}
		addrs = append(addrs, c.Addr)
	}

	ups, err := f.buildUpstreamGroup(addrs)
	if err != nil {
		return nil, err
	}
	f.rawUpstreams = ups
	f.upstreamsCloser = append(f.upstreamsCloser, ups...)

	bp.L().Info("adg_forward initialized",
		zap.Int("upstreams", len(args.Upstream)),
		zap.String("mode", string(args.Mode)),
		zap.Int("bootstrap", len(args.Bootstrap)),
		zap.Bool("client_id_passthrough", args.ClientIDPassthrough),
	)

	return f, nil
}

// buildUpstreamGroup 用与 base upstream 完全相同的参数，为一组 addr 构建一组
// dnsproxy upstream。addrs 与 f.args.Upstream 按顺序一一对应，从而保持每个
// 上游各自的 HTTP3/InsecureSkipVerify 配置不变。
func (f *adgForward) buildUpstreamGroup(addrs []string) ([]dnsproxy_upstream.Upstream, error) {
	if len(addrs) != len(f.args.Upstream) {
		return nil, fmt.Errorf("internal: upstream addr count mismatch: %d != %d", len(addrs), len(f.args.Upstream))
	}

	ups := make([]dnsproxy_upstream.Upstream, 0, len(addrs))
	for i, addr := range addrs {
		c := f.args.Upstream[i]
		opts := &dnsproxy_upstream.Options{
			Timeout:            f.timeout,
			InsecureSkipVerify: c.InsecureSkipVerify,
			Bootstrap:          f.bootstrap,
		}
		if c.HTTP3 {
			opts.HTTPVersions = []dnsproxy_upstream.HTTPVersion{
				dnsproxy_upstream.HTTPVersion3,
			}
		}

		u, err := dnsproxy_upstream.AddressToUpstream(addr, opts)
		if err != nil {
			// 回滚已创建的上游，避免连接池泄漏。
			for _, built := range ups {
				built.Close()
			}
			return nil, fmt.Errorf("failed to init upstream %s: %w", addr, err)
		}
		ups = append(ups, u)
	}
	return ups, nil
}

// Exec 根据 mode 选择查询策略。
func (f *adgForward) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()

	f.L().Info("adg_forward: query",
		zap.String("host", q.Question[0].Name),
		zap.String("qtype", dns.Type(q.Question[0].Qtype).String()),
		zap.String("mode", string(f.mode)),
		qCtx.InfoField(),
	)

	var r *dns.Msg
	var err error

	upstreams := f.rawUpstreams
	if f.passthroughCache != nil {
		ids := qCtx.ReqMeta().GetClientIDs()
		if len(ids) > 0 {
			upstreams, err = f.upstreamsForIDs(ids)
			if err != nil {
				return fmt.Errorf("adg_forward: build client_id variant: %w", err)
			}
		}
	}

	switch f.mode {
	case ModeParallel:
		r, err = f.execParallel(q, upstreams)
	case ModeFastestAddr:
		r, err = f.execFastestAddr(q, upstreams)
	default: // ModeLoadBalance
		r, err = f.execLoadBalance(q, upstreams)
	}

	if err != nil {
		return err
	}

	qCtx.SetResponse(r)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

// execParallel 并发查询所有 upstream，返回第一个成功响应。
func (f *adgForward) execParallel(q *dns.Msg, upstreams []dnsproxy_upstream.Upstream) (*dns.Msg, error) {
	r, resolved, err := dnsproxy_upstream.ExchangeParallel(upstreams, q.Copy())
	if err != nil {
		return nil, err
	}
	addr := ""
	if resolved != nil {
		addr = resolved.Address()
	}
	f.L().Info("adg_forward: forwarded (parallel)",
		zap.String("upstream", addr),
	)
	return r, nil
}

// execFastestAddr 查询所有 upstream，对返回的 IP 地址 ping 测速，返回最快 IP 的响应。
func (f *adgForward) execFastestAddr(q *dns.Msg, upstreams []dnsproxy_upstream.Upstream) (*dns.Msg, error) {
	r, resolved, err := f.fastestAddr.ExchangeFastest(q, upstreams)
	if err != nil {
		return nil, err
	}
	addr := ""
	if resolved != nil {
		addr = resolved.Address()
	}
	f.L().Info("adg_forward: forwarded (fastest_addr)",
		zap.String("upstream", addr),
	)
	return r, nil
}

// execLoadBalance 基于 RTT 加权随机选择一个 upstream 查询。
func (f *adgForward) execLoadBalance(q *dns.Msg, upstreams []dnsproxy_upstream.Upstream) (*dns.Msg, error) {
	if len(upstreams) == 1 {
		addr := upstreams[0].Address()
		start := time.Now()
		r, err := upstreams[0].Exchange(q)
		elapsed := time.Since(start)
		if err != nil {
			f.L().Warn("adg_forward: upstream error",
				zap.String("upstream", addr),
				zap.Duration("rtt", elapsed),
				zap.Error(err),
			)
			return nil, err
		}
		f.L().Info("adg_forward: forwarded",
			zap.String("upstream", addr),
			zap.Duration("rtt", elapsed),
		)
		return r, nil
	}

	// 加权随机选择
	weights := make([]float64, len(upstreams))
	f.rttLock.Lock()
	for i := range upstreams {
		addr := upstreams[i].Address()
		stats := f.rttStatsMap[addr]
		if stats == nil {
			weights[i] = 1
		} else {
			weights[i] = stats.weight()
		}
	}
	f.rttLock.Unlock()

	idx := weightedSelect(weights)
	start := time.Now()
	r, err := upstreams[idx].Exchange(q)

	// 更新 RTT 统计
	elapsed := time.Since(start)
	addr := upstreams[idx].Address()

	f.rttLock.Lock()
	stats, ok := f.rttStatsMap[addr]
	if !ok {
		stats = new(rttStats)
		f.rttStatsMap[addr] = stats
	}
	f.rttLock.Unlock()
	stats.update(elapsed)

	if err != nil {
		f.L().Warn("adg_forward: upstream error",
			zap.String("upstream", addr),
			zap.Duration("rtt", elapsed),
			zap.Error(err),
		)
		return nil, err
	}

	f.L().Info("adg_forward: forwarded",
		zap.String("upstream", addr),
		zap.Duration("rtt", elapsed),
	)
	return r, nil
}

// weightedSelect 根据权重切片随机选择一个下标。
func weightedSelect(weights []float64) int {
	var total float64
	for _, w := range weights {
		total += w
	}
	r := rand.Float64() * total
	var cum float64
	for i, w := range weights {
		cum += w
		if r < cum {
			return i
		}
	}
	return len(weights) - 1
}

func (f *adgForward) Shutdown() error {
	for _, u := range f.upstreamsCloser {
		u.Close()
	}
	// 关闭所有 client_id 变体 upstream（Clean 逐出时经 onEvict 触发 Close）。
	if f.passthroughCache != nil {
		f.passthroughCache.Clean(func(_ string, _ []dnsproxy_upstream.Upstream) bool {
			return true
		})
	}
	return nil
}
