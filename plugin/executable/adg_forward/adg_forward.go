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
}

type UpstreamConfig struct {
	Addr               string `yaml:"addr"`                // required
	HTTP3              bool   `yaml:"http3"`               // enable HTTP/3
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	Trusted            bool   `yaml:"trusted"`             // 未配置时第一个 upstream 强制 trusted
}

type rttStats struct {
	mu        sync.Mutex
	rttSum    float64 // 微秒累计
	reqNum    float64
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

	// fastest_addr 模式
	fastestAddr *fastip.FastestAddr

	// load_balance 模式
	rttLock   sync.Mutex
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
		BP:   bp,
		args: args,
		mode: args.Mode,
	}

	if args.Mode == ModeFastestAddr {
		f.fastestAddr = fastip.New(&fastip.Config{})
	}

	if args.Mode == ModeLoadBalance {
		f.rttStatsMap = make(map[string]*rttStats)
	}

	// ── Build global bootstrap pool ──────────────────────────────────────
	var globalBootstrap dnsproxy_upstream.Resolver
	if len(args.Bootstrap) > 0 {
		bsOpts := &dnsproxy_upstream.Options{
			Timeout: timeout,
		}

		if len(args.Bootstrap) == 1 {
			r, err := dnsproxy_upstream.NewUpstreamResolver(args.Bootstrap[0], bsOpts)
			if err != nil {
				return nil, fmt.Errorf("failed to create bootstrap resolver %s: %w", args.Bootstrap[0], err)
			}
			globalBootstrap = dnsproxy_upstream.NewCachingResolver(r)
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
			globalBootstrap = &pr
		}
	}

	// ── Build each upstream ──────────────────────────────────────────────
	for i, c := range args.Upstream {
		if len(c.Addr) == 0 {
			return nil, errors.New("missing upstream addr")
		}

		opts := &dnsproxy_upstream.Options{
			Timeout:            timeout,
			InsecureSkipVerify: c.InsecureSkipVerify,
			Bootstrap:          globalBootstrap,
		}

		if c.HTTP3 {
			opts.HTTPVersions = []dnsproxy_upstream.HTTPVersion{
				dnsproxy_upstream.HTTPVersion3,
			}
		}

		u, err := dnsproxy_upstream.AddressToUpstream(c.Addr, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream %s: %w", c.Addr, err)
		}

		_ = i // 当前模式下不需要 upstreamWrapper，直接用 rawUpstreams
		f.rawUpstreams = append(f.rawUpstreams, u)
		f.upstreamsCloser = append(f.upstreamsCloser, u)
	}

	bp.L().Info("adg_forward initialized",
		zap.Int("upstreams", len(args.Upstream)),
		zap.String("mode", string(args.Mode)),
		zap.Int("bootstrap", len(args.Bootstrap)),
	)

	return f, nil
}

// Exec 根据 mode 选择查询策略。
func (f *adgForward) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()

	var r *dns.Msg
	var err error

	switch f.mode {
	case ModeParallel:
		r, err = f.execParallel(q)
	case ModeFastestAddr:
		r, err = f.execFastestAddr(q)
	default: // ModeLoadBalance
		r, err = f.execLoadBalance(q)
	}

	if err != nil {
		return err
	}

	qCtx.SetResponse(r)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

// execParallel 并发查询所有 upstream，返回第一个成功响应。
func (f *adgForward) execParallel(q *dns.Msg) (*dns.Msg, error) {
	r, _, err := dnsproxy_upstream.ExchangeParallel(f.rawUpstreams, q.Copy())
	if err != nil {
		return nil, err
	}
	return r, nil
}

// execFastestAddr 查询所有 upstream，对返回的 IP 地址 ping 测速，返回最快 IP 的响应。
func (f *adgForward) execFastestAddr(q *dns.Msg) (*dns.Msg, error) {
	r, _, err := f.fastestAddr.ExchangeFastest(q, f.rawUpstreams)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// execLoadBalance 基于 RTT 加权随机选择一个 upstream 查询。
func (f *adgForward) execLoadBalance(q *dns.Msg) (*dns.Msg, error) {
	if len(f.rawUpstreams) == 1 {
		r, err := f.rawUpstreams[0].Exchange(q)
		if err != nil {
			return nil, err
		}
		return r, nil
	}

	// 加权随机选择
	weights := make([]float64, len(f.rawUpstreams))
	f.rttLock.Lock()
	for i := range f.rawUpstreams {
		addr := f.rawUpstreams[i].Address()
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
	r, err := f.rawUpstreams[idx].Exchange(q)

	// 更新 RTT 统计
	elapsed := time.Since(start)
	addr := f.rawUpstreams[idx].Address()

	f.rttLock.Lock()
	stats, ok := f.rttStatsMap[addr]
	if !ok {
		stats = new(rttStats)
		f.rttStatsMap[addr] = stats
	}
	f.rttLock.Unlock()
	stats.update(elapsed)

	if err != nil {
		return nil, err
	}
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
	return nil
}
