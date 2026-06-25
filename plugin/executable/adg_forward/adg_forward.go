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
	"time"

	"github.com/miekg/dns"

	dnsproxy_upstream "github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/bundled_upstream"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "adg_forward"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*adgForward)(nil)

type Args struct {
	// 上游地址列表。
	Upstream []UpstreamConfig `yaml:"upstream"`
	// 全局 bootstrap pool。该列表中的每个地址（必须是纯 IP）会被创建为一个
	// bootstrap resolver，所有上游共享它们做并发域名解析。
	Bootstrap []string `yaml:"bootstrap"`
	// 全局超时（秒），默认 5。
	Timeout int `yaml:"timeout"`
}

type UpstreamConfig struct {
	Addr               string `yaml:"addr"`                // required
	HTTP3              bool   `yaml:"http3"`               // enable HTTP/3
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	Trusted            bool   `yaml:"trusted"`             // 未配置时第一个 upstream 强制 trusted
}

type adgForward struct {
	*coremain.BP
	args *Args

	upstreamWrappers []bundled_upstream.Upstream
	upstreamsCloser  []dnsproxy_upstream.Upstream
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

	f := &adgForward{
		BP:   bp,
		args: args,
	}

	// ── Build global bootstrap pool ──────────────────────────────────────
	var globalBootstrap dnsproxy_upstream.Resolver // nil initially
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

		w := &upstreamWrapper{
			address: c.Addr,
			trusted: c.Trusted,
			u:       u,
		}
		if i == 0 {
			w.trusted = true // first upstream is always trusted
		}

		f.upstreamWrappers = append(f.upstreamWrappers, w)
		f.upstreamsCloser = append(f.upstreamsCloser, u)
	}

	return f, nil
}

type upstreamWrapper struct {
	address string
	trusted bool
	u       dnsproxy_upstream.Upstream
}

func (w *upstreamWrapper) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	q.Compress = true
	return w.u.Exchange(q)
}

func (w *upstreamWrapper) Address() string {
	return w.address
}

func (w *upstreamWrapper) Trusted() bool {
	return w.trusted
}

func (f *adgForward) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	r, err := bundled_upstream.ExchangeParallel(ctx, qCtx, f.upstreamWrappers, f.L())
	if err != nil {
		return err
	}
	qCtx.SetResponse(r)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (f *adgForward) Shutdown() error {
	for _, u := range f.upstreamsCloser {
		u.Close()
	}
	return nil
}
