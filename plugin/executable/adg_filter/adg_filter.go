package adg_filter

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "adg_filter"

func init() {
	var err error
	BlockedMark, err = query_context.AllocateMark()
	if err != nil {
		panic(fmt.Sprintf("adg_filter: %v", err))
	}
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var BlockedMark uint
var _ coremain.ExecutablePlugin = (*adgFilter)(nil)

type FilterListConfig struct {
	URL     string `yaml:"url"`
	Name    string `yaml:"name"`
	ID      int    `yaml:"id"`
	Enabled *bool  `yaml:"enabled,omitempty"`
}

type Args struct {
	BlockLists    []FilterListConfig `yaml:"block_lists"`
	BlockProvider []string           `yaml:"block_provider"`

	AllowLists    []FilterListConfig `yaml:"allow_lists"`
	AllowProvider []string           `yaml:"allow_provider"`

	BlockMode      string `yaml:"block_mode"`
	BlockingIPv4   string `yaml:"blocking_ipv4"`
	BlockingIPv6   string `yaml:"blocking_ipv6"`
	UpdateInterval int    `yaml:"update_interval"`
	CacheDir       string `yaml:"cache_dir"`
}

type adgFilter struct {
	*coremain.BP
	args *Args

	blockMG *domain.MatcherGroup[struct{}]
	allowMG *domain.MatcherGroup[struct{}]

	blockListsDM *domain.DynamicMatcher[struct{}] // lists+inline, bg updater
	allowListsDM *domain.DynamicMatcher[struct{}]

	blockProvMG *domain.MatcherGroup[struct{}] // provider entries
	allowProvMG *domain.MatcherGroup[struct{}]

	blockingIPv4 netip.Addr
	blockingIPv6 netip.Addr

	cancel context.CancelFunc
	done   chan struct{}
}

func (f *adgFilter) Close() error {
	if f.cancel != nil {
		f.cancel()
		if f.done != nil {
			<-f.done
		}
	}
	if f.blockProvMG != nil {
		f.blockProvMG.Close()
	}
	if f.allowProvMG != nil {
		f.allowProvMG.Close()
	}
	return nil
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)

	if a.BlockMode == "" {
		a.BlockMode = "nxdomain"
	}
	if a.BlockingIPv4 == "" {
		a.BlockingIPv4 = "0.0.0.0"
	}
	if a.BlockingIPv6 == "" {
		a.BlockingIPv6 = "::"
	}
	if a.UpdateInterval <= 0 {
		a.UpdateInterval = 86400
	}

	ipv4, err := netip.ParseAddr(a.BlockingIPv4)
	if err != nil {
		return nil, fmt.Errorf("invalid blocking_ipv4 %s: %w", a.BlockingIPv4, err)
	}
	if !ipv4.Is4() {
		return nil, fmt.Errorf("blocking_ipv4 %s is not a valid IPv4 address", a.BlockingIPv4)
	}
	ipv6, err := netip.ParseAddr(a.BlockingIPv6)
	if err != nil {
		return nil, fmt.Errorf("invalid blocking_ipv6 %s: %w", a.BlockingIPv6, err)
	}
	if !ipv6.Is6() {
		return nil, fmt.Errorf("blocking_ipv6 %s is not a valid IPv6 address", a.BlockingIPv6)
	}

	f := &adgFilter{
		BP:           bp,
		args:         a,
		blockingIPv4: ipv4,
		blockingIPv6: ipv6,
	}

	// ── Block MatcherGroup ──────────────────────────────────────
	blockMG := &domain.MatcherGroup[struct{}]{}

	if len(a.BlockLists) > 0 {
		f.blockListsDM = domain.NewDynamicMatcher[struct{}](domainTextParser)
		if data, dErr := f.loadOrRebuildDomains(a.BlockLists, "adg_filter_block.domains"); dErr == nil {
			if uErr := f.blockListsDM.Update(data); uErr != nil {
				f.L().Warn("failed to load block domains", zap.Error(uErr))
			}
		}
		blockMG.Append(f.blockListsDM)
	}

	if len(a.BlockProvider) > 0 {
		var err error
		f.blockProvMG, err = domain.BatchLoadDomainProvider(a.BlockProvider, bp.M().GetDataManager())
		if err != nil {
			return nil, fmt.Errorf("block_provider: %w", err)
		}
		blockMG.Append(f.blockProvMG)
		f.L().Info("block provider loaded", zap.Int("providers", len(a.BlockProvider)))
	}

	if blockMG.Len() > 0 {
		f.blockMG = blockMG
	}

	// ── Allow MatcherGroup ─────────────────────────────────────
	allowMG := &domain.MatcherGroup[struct{}]{}

	if len(a.AllowLists) > 0 {
		f.allowListsDM = domain.NewDynamicMatcher[struct{}](domainTextParser)
		if data, dErr := f.loadOrRebuildDomains(a.AllowLists, "adg_filter_allow.domains"); dErr == nil {
			if uErr := f.allowListsDM.Update(data); uErr != nil {
				f.L().Warn("failed to load allow domains", zap.Error(uErr))
			}
		}
		allowMG.Append(f.allowListsDM)
	}

	if len(a.AllowProvider) > 0 {
		var err error
		f.allowProvMG, err = domain.BatchLoadDomainProvider(a.AllowProvider, bp.M().GetDataManager())
		if err != nil {
			return nil, fmt.Errorf("allow_provider: %w", err)
		}
		allowMG.Append(f.allowProvMG)
		f.L().Info("allow provider loaded", zap.Int("providers", len(a.AllowProvider)))
	}

	if allowMG.Len() > 0 {
		f.allowMG = allowMG
	}

	if len(a.BlockLists) > 0 || len(a.AllowLists) > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		f.cancel = cancel
		f.done = make(chan struct{})
		go f.runBackground(ctx)
	}

	return f, nil
}

func (f *adgFilter) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if len(q.Question) != 1 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	question := q.Question[0]
	hostname := strings.TrimSuffix(question.Name, ".")
	qtype := question.Qtype

	if hostname == "" {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	if f.blockMG != nil {
		if _, matched := f.blockMG.Match(hostname); matched {
			if f.allowMG != nil {
				if _, allowed := f.allowMG.Match(hostname); allowed {
					f.L().Info("adg_filter: allowlist hit, pass through",
						zap.String("host", hostname),
						zap.String("qtype", dns.Type(qtype).String()),
					)
					return executable_seq.ExecChainNode(ctx, qCtx, next)
				}
			}
			f.L().Info("adg_filter: blocklist hit, blocked",
				zap.String("host", hostname),
				zap.String("qtype", dns.Type(qtype).String()),
			)
			qCtx.AddMark(BlockedMark)
			f.applyBlock(qCtx, q, qtype)
			return nil
		}
	}

	f.L().Debug("adg_filter: no match, pass through",
		zap.String("host", hostname),
		zap.String("qtype", dns.Type(qtype).String()),
	)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (f *adgFilter) applyBlock(qCtx *query_context.Context, q *dns.Msg, qtype uint16) {
	qName := q.Question[0].Name

	switch f.args.BlockMode {
	case "nxdomain":
		r := dnsutils.GenEmptyReply(q, dns.RcodeNameError)
		qCtx.SetResponse(r)

	case "refused":
		r := dnsutils.GenEmptyReply(q, dns.RcodeRefused)
		qCtx.SetResponse(r)

	case "zero_ip", "custom_ip":
		switch qtype {
		case dns.TypeA:
			r := new(dns.Msg)
			r.SetRcode(q, dns.RcodeSuccess)
			r.RecursionAvailable = true
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: f.blockingIPv4.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
			qCtx.SetResponse(r)

		case dns.TypeAAAA:
			r := new(dns.Msg)
			r.SetRcode(q, dns.RcodeSuccess)
			r.RecursionAvailable = true
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				AAAA: f.blockingIPv6.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
			qCtx.SetResponse(r)

		default:
			r := dnsutils.GenEmptyReply(q, dns.RcodeNameError)
			qCtx.SetResponse(r)
		}

	default:
		r := dnsutils.GenEmptyReply(q, dns.RcodeNameError)
		qCtx.SetResponse(r)
	}
}

func (f *adgFilter) runBackground(ctx context.Context) {
	defer close(f.done)

	f.L().Info("adg_filter: starting background filter update")
	f.updateMatchers()

	ticker := time.NewTicker(time.Duration(f.args.UpdateInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.updateMatchers()
		}
	}
}

func (f *adgFilter) updateMatchers() {
	if f.blockListsDM != nil {
		if data, err := f.loadOrRebuildDomains(f.args.BlockLists, "adg_filter_block.domains"); err == nil {
			if uErr := f.blockListsDM.Update(data); uErr != nil {
				f.L().Warn("block lists update failed", zap.Error(uErr))
			} else {
				f.L().Info("block lists updated")
			}
		} else {
			f.L().Warn("block lists rebuild failed", zap.Error(err))
		}
	}

	if f.allowListsDM != nil {
		if data, err := f.loadOrRebuildDomains(f.args.AllowLists, "adg_filter_allow.domains"); err == nil {
			if uErr := f.allowListsDM.Update(data); uErr != nil {
				f.L().Warn("allow lists update failed", zap.Error(uErr))
			} else {
				f.L().Info("allow lists updated")
			}
		} else {
			f.L().Warn("allow lists rebuild failed", zap.Error(err))
		}
	}
}
