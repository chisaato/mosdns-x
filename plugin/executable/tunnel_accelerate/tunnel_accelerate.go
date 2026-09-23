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

// Package tunnel_accelerate implements the "domestic tunnel accelerate"
// service. Domains registered in the hosts file are probed with TCP dials
// to decide whether the tunnel endpoint is alive. When alive, queries are
// answered with the tunnel IPs (hosts-style answer); when dead, queries
// fall through to the next node in the chain (back to public resolution).
// TYPE65 (HTTPS) queries are answered with an empty NOERROR while the
// tunnel is alive, to suppress ECH public key distribution.
package tunnel_accelerate

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
	"github.com/pmkol/mosdns-x/pkg/data_provider"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/hosts"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "tunnel_accelerate"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*tunnelAccelerate)(nil)

type Args struct {
	// Hosts contains data provider references ("provider:xxx") or inline
	// text entries in hosts format: one "fqdn ip1 ip2 ..." per line.
	Hosts []string `yaml:"hosts"`
	// TTL is the answer ttl in seconds. Default 30.
	TTL int `yaml:"ttl"`
	// ProbePort is the default tcp probe port. Default 443.
	ProbePort int `yaml:"probe_port"`
	// ProbePortMap overrides the probe port per exact FQDN.
	ProbePortMap map[string]int `yaml:"probe_port_map"`
	// ProbeTimeout is the per-dial timeout in seconds. Default 1.
	ProbeTimeout int `yaml:"probe_timeout"`
	// ProbeCacheSize is the probe result LRU capacity. Default 1024.
	ProbeCacheSize int `yaml:"probe_cache_size"`
	// ProbeCacheTTL is the probe result cache ttl in seconds. Default 60.
	ProbeCacheTTL int `yaml:"probe_cache_ttl"`
}

type probeCacheEntry struct {
	alive    bool
	expireAt time.Time
}

// dialProbeFunc reports whether a tcp endpoint is alive.
// It is a package level variable so that unit tests can inject fake probes.
type dialProbeFunc func(ctx context.Context, ip string, port int, timeout time.Duration) bool

var defaultDialProbe dialProbeFunc = func(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close() // dial succeeded, the endpoint is alive
	return true
}

type tunnelAccelerate struct {
	*coremain.BP
	args *Args

	hostsMatcher  domain.Matcher[*hosts.IPs]
	matcherCloser interface{ Close() error }

	probePortMap map[string]int
	probeTimeout time.Duration
	cacheTTL     time.Duration

	dialProbe dialProbeFunc
	cache     *concurrent_lru.ConcurrentLRU[string, *probeCacheEntry]
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newTunnelAccelerate(bp, args.(*Args))
}

func newTunnelAccelerate(bp *coremain.BP, args *Args) (*tunnelAccelerate, error) {
	if args.TTL <= 0 {
		args.TTL = 30
	}
	if args.ProbePort <= 0 {
		args.ProbePort = 443
	}
	if args.ProbeTimeout <= 0 {
		args.ProbeTimeout = 1
	}
	if args.ProbeCacheSize <= 0 {
		args.ProbeCacheSize = 1024
	}
	if args.ProbeCacheTTL <= 0 {
		args.ProbeCacheTTL = 60
	}

	portMap := make(map[string]int, len(args.ProbePortMap))
	for fqdn, port := range args.ProbePortMap {
		if port <= 0 {
			continue
		}
		portMap[dns.Fqdn(fqdn)] = port
	}

	t := &tunnelAccelerate{
		BP:           bp,
		args:         args,
		probePortMap: portMap,
		probeTimeout: time.Duration(args.ProbeTimeout) * time.Second,
		cacheTTL:     time.Duration(args.ProbeCacheTTL) * time.Second,
		dialProbe:    defaultDialProbe,
		cache:        concurrent_lru.NewConecurrentLRU[string, *probeCacheEntry](args.ProbeCacheSize, nil),
	}

	if len(args.Hosts) > 0 {
		var dm *data_provider.DataManager
		if bp.M() != nil {
			dm = bp.M().GetDataManager()
		}

		staticMatcher := domain.NewMixMatcher[*hosts.IPs]()
		staticMatcher.SetDefaultMatcher(domain.MatcherFull)
		m, err := domain.BatchLoadProvider[*hosts.IPs](
			args.Hosts,
			staticMatcher,
			hosts.ParseIPs,
			dm,
			func(b []byte) (domain.Matcher[*hosts.IPs], error) {
				mixMatcher := domain.NewMixMatcher[*hosts.IPs]()
				mixMatcher.SetDefaultMatcher(domain.MatcherFull)
				if err := domain.LoadFromTextReader[*hosts.IPs](mixMatcher, bytes.NewReader(b), hosts.ParseIPs); err != nil {
					return nil, err
				}
				return mixMatcher, nil
			},
		)
		if err != nil {
			return nil, err
		}
		t.hostsMatcher = m
		t.matcherCloser = m
		bp.L().Info("tunnel_accelerate: hosts loaded", zap.Int("count", m.Len()))
	}

	return t, nil
}

func (t *tunnelAccelerate) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if len(q.Question) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// Exact match the query name against the hosts matcher.
	fqdn := dns.Fqdn(q.Question[0].Name)
	entry, ok := t.lookup(fqdn)
	if !ok {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}
	ipv4, ipv6 := entry.IPv4, entry.IPv6
	if len(ipv4)+len(ipv6) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// Decide per question; take over the query if any question says so.
	var answers []dns.RR
	takeOver := false
	for i := range q.Question {
		switch q.Question[i].Qtype {
		case dns.TypeHTTPS:
			// Any endpoint alive: suppress ECH key distribution
			// with an empty NOERROR.
			if t.probeAnyAlive(ctx, fqdn, ipv4, ipv6) {
				takeOver = true
			}
		case dns.TypeA:
			rrs, takeover := t.decideAddrFamily(ctx, fqdn, ipv4, ipv6, false)
			if takeover {
				takeOver = true
				answers = append(answers, rrs...)
			}
		case dns.TypeAAAA:
			rrs, takeover := t.decideAddrFamily(ctx, fqdn, ipv6, ipv4, true)
			if takeover {
				takeOver = true
				answers = append(answers, rrs...)
			}
		default:
			// other qtypes fall through
		}
	}

	if !takeOver {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	t.setReply(qCtx, answers)
	return nil
}

// lookup exact matches fqdn in the hosts matcher.
func (t *tunnelAccelerate) lookup(fqdn string) (*hosts.IPs, bool) {
	if t.hostsMatcher == nil {
		return nil, false
	}
	return t.hostsMatcher.Match(fqdn)
}

// decideAddrFamily probes the primary family (the queried one). It returns
// records for the alive primary IPs, or a suppress decision (empty NOERROR)
// when the primary family is dead/unconfigured but the secondary family has
// at least one alive IP. It returns no takeover when both families are dead,
// so the query falls through to the next node.
func (t *tunnelAccelerate) decideAddrFamily(ctx context.Context, fqdn string, primary, secondary []netip.Addr, isAAAA bool) (rrs []dns.RR, takeOver bool) {
	port := t.probePortFor(fqdn)

	if len(primary) > 0 {
		alive := t.probeAliveIPs(ctx, primary, port)
		if len(alive) > 0 {
			return t.buildAddrRRs(fqdn, alive, isAAAA), true
		}
	}

	// Primary family unconfigured or all dead: suppress this family
	// if the other family is still alive.
	if len(secondary) > 0 && len(t.probeAliveIPs(ctx, secondary, port)) > 0 {
		return nil, true
	}

	// Whole domain dead: fall back to the next node.
	return nil, false
}

// probeAnyAlive reports whether any of the ips is alive.
func (t *tunnelAccelerate) probeAnyAlive(ctx context.Context, fqdn string, ipv4, ipv6 []netip.Addr) bool {
	all := make([]netip.Addr, 0, len(ipv4)+len(ipv6))
	all = append(all, ipv4...)
	all = append(all, ipv6...)
	return len(t.probeAliveIPs(ctx, all, t.probePortFor(fqdn))) > 0
}

// probeAliveIPs probes all ips concurrently and returns the alive ones
// in their original order.
func (t *tunnelAccelerate) probeAliveIPs(ctx context.Context, ips []netip.Addr, port int) []netip.Addr {
	if len(ips) == 0 {
		return nil
	}

	results := make([]bool, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip netip.Addr) {
			defer wg.Done()
			results[i] = t.probeIP(ctx, ip, port)
		}(i, ip)
	}
	wg.Wait()

	var alive []netip.Addr
	for i, ok := range results {
		if ok {
			alive = append(alive, ips[i])
		}
	}
	return alive
}

// probeIP probes a single ip:port endpoint, with an LRU+TTL cache
// in front of the actual dial.
func (t *tunnelAccelerate) probeIP(ctx context.Context, ip netip.Addr, port int) bool {
	key := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	now := time.Now()

	if entry, ok := t.cache.Get(key); ok && now.Before(entry.expireAt) {
		return entry.alive
	}

	alive := t.dialProbe(ctx, ip.String(), port, t.probeTimeout)
	t.cache.Add(key, &probeCacheEntry{
		alive:    alive,
		expireAt: now.Add(t.cacheTTL),
	})
	return alive
}

// probePortFor returns the probe port for the exact fqdn.
func (t *tunnelAccelerate) probePortFor(fqdn string) int {
	if port, ok := t.probePortMap[fqdn]; ok && port > 0 {
		return port
	}
	return t.args.ProbePort
}

// buildAddrRRs builds A/AAAA records for ips with Args.TTL.
func (t *tunnelAccelerate) buildAddrRRs(fqdn string, ips []netip.Addr, isAAAA bool) []dns.RR {
	rrs := make([]dns.RR, 0, len(ips))
	for _, ip := range ips {
		hdr := dns.RR_Header{
			Name:  fqdn,
			Class: dns.ClassINET,
			Ttl:   uint32(t.args.TTL),
		}
		if isAAAA {
			hdr.Rrtype = dns.TypeAAAA
			rrs = append(rrs, &dns.AAAA{Hdr: hdr, AAAA: ip.AsSlice()})
		} else {
			hdr.Rrtype = dns.TypeA
			rrs = append(rrs, &dns.A{Hdr: hdr, A: ip.AsSlice()})
		}
	}
	return rrs
}

// setReply takes over the query: writes an answer (or an empty NOERROR
// when answers is nil, following ech_block's empty block mode) to qCtx.
func (t *tunnelAccelerate) setReply(qCtx *query_context.Context, answers []dns.RR) {
	q := qCtx.Q()
	r := qCtx.R()
	if r == nil {
		r = new(dns.Msg)
	}
	r.SetReply(q)
	r.RecursionAvailable = true
	// The Answer section is fully owned by this plugin when it takes over.
	r.Answer = answers
	qCtx.SetResponse(r)
}

func (t *tunnelAccelerate) Close() error {
	if t.matcherCloser != nil {
		return t.matcherCloser.Close()
	}
	return nil
}
