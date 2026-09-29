package adg_cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "adg_cache"

const (
	defaultSize            = 52428800 // 50MB
	defaultPrefetchTTL     = 10
	defaultStaleTTL        = 300
	defaultOptimisticTTL   = 30
	defaultPrefetchTimeout = time.Second * 5
)

// cache entry value layout:
// [0:4]  expiry unix timestamp, big-endian uint32
// [4:6]  packed dns msg length, big-endian uint16
// [6:]   packed dns msg bytes

var _ coremain.ExecutablePlugin = (*adgCachePlugin)(nil)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	Size          int  `yaml:"size"`
	Prefetch      bool `yaml:"prefetch"`
	PrefetchTTL   int  `yaml:"prefetch_ttl"`
	StaleTTL      int  `yaml:"stale_ttl"`
	OptimisticTTL int  `yaml:"optimistic_ttl"`
	// Optimistic controls whether expired cache is served when still within
	// StaleTTL.  Default true (serve expired but with OptimisticTTL-adjusted
	// TTL so the client doesn't cache our stale value too long).
	// A pointer so that an explicit false can be told apart from unset.
	Optimistic *bool `yaml:"optimistic"`
	// StaleMinTTL: only entries whose stored ttl is greater than this are
	// served stale. A short ttl is a short-lived decision (e.g. a probe
	// gate), and serving it stale would extend it past its own validity.
	// 0 means OptimisticTTL, < 0 serves every entry stale.
	StaleMinTTL int `yaml:"stale_min_ttl"`
}

type adgCachePlugin struct {
	*coremain.BP
	args *Args

	items          glcache.Cache
	metrics        *cacheMetrics
	prefetchSF     singleflight.Group
	prefetchCtx    context.Context
	prefetchCancel context.CancelFunc
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newAdgCachePlugin(bp, args.(*Args))
}

func newAdgCachePlugin(bp *coremain.BP, args *Args) (*adgCachePlugin, error) {
	if args.Size <= 0 {
		args.Size = defaultSize
	}
	if args.PrefetchTTL <= 0 {
		args.PrefetchTTL = defaultPrefetchTTL
	}
	if args.StaleTTL <= 0 {
		args.StaleTTL = defaultStaleTTL
	}
	if args.OptimisticTTL <= 0 {
		args.OptimisticTTL = defaultOptimisticTTL
	}
	// Default to optimistic (serve stale).
	if args.Optimistic == nil {
		optimistic := true
		args.Optimistic = &optimistic
	}
	if args.StaleMinTTL == 0 {
		args.StaleMinTTL = args.OptimisticTTL
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &adgCachePlugin{
		BP:             bp,
		args:           args,
		metrics:        newCacheMetrics(),
		prefetchCtx:    ctx,
		prefetchCancel: cancel,
	}
	p.items = glcache.New(glcache.Config{
		MaxSize:   uint(args.Size),
		EnableLRU: true,
		OnDelete:  p.onEvict,
	})
	if err := p.registerMetrics(); err != nil {
		cancel()
		return nil, fmt.Errorf("adg_cache: register metrics: %w", err)
	}
	return p, nil
}

func (f *adgCachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()

	if !isCacheable(q) {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	key, err := f.getCacheKey(q, strings.Join(qCtx.ReqMeta().GetClientIDs(), "/"))
	if err != nil {
		f.L().Warn("adg_cache: get msg key", qCtx.InfoField(), zap.Error(err))
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	f.metrics.queryTotal.Inc()
	cached := f.items.Get([]byte(key))
	if cached != nil {
		msg, expiry, err := unpackCacheValue(cached)
		if err != nil {
			f.L().Warn("adg_cache: unpack cached value", qCtx.InfoField(), zap.Error(err))
			return executable_seq.ExecChainNode(ctx, qCtx, next)
		}

		now := uint32(time.Now().Unix())
		// The stored msg keeps the ttl it had when it was cached.
		origTTL := dnsutils.GetMinimalTTL(msg)

		// Fresh entry (not expired): serve directly.
		if now < expiry {
			remaining := expiry - now
			if remaining < origTTL {
				dnsutils.SubtractTTL(msg, origTTL-remaining)
			}
			msg.Id = q.Id
			qCtx.SetResponse(msg)
			f.metrics.hitTotal.Inc()
			f.L().Debug("adg_cache: fresh hit", qCtx.InfoField())

			// Prefetch: refresh a hit entry shortly before it expires, so
			// hot entries never go stale. Entries whose whole ttl fits in
			// the window are skipped, or every hit would refresh them.
			if f.args.Prefetch && remaining <= uint32(f.args.PrefetchTTL) && origTTL > uint32(f.args.PrefetchTTL) {
				f.doRefresh(key, qCtx, next)
			}
			return nil
		}

		// Expired entry.
		expiredSec := now - expiry

		if f.canServeStale(origTTL, expiredSec) {
			dnsutils.SetTTL(msg, uint32(f.args.OptimisticTTL))
			msg.Id = q.Id
			qCtx.SetResponse(msg)
			f.metrics.staleHitTotal.Inc()
			f.L().Debug("adg_cache: stale hit",
				qCtx.InfoField(),
				zap.Uint32("expired_sec", expiredSec),
			)

			// Always refresh in the background, so a stale entry is served
			// only until the refresh lands, not for the whole StaleTTL.
			f.doRefresh(key, qCtx, next)
			return nil
		}

		// Not servable stale: treat as miss.
		f.L().Debug("adg_cache: miss (expired, not served stale)", qCtx.InfoField())
	}

	// Cache miss: run next chain node, store result if valid.
	err = executable_seq.ExecChainNode(ctx, qCtx, next)
	r := qCtx.R()
	if r != nil {
		if storeErr := f.tryStore(key, r); storeErr != nil {
			f.L().Warn("adg_cache: store", qCtx.InfoField(), zap.Error(storeErr))
		}
	}
	return err
}

// canServeStale reports whether an entry cached with origTTL and expired
// expiredSec seconds ago may be served stale.
func (f *adgCachePlugin) canServeStale(origTTL, expiredSec uint32) bool {
	if !*f.args.Optimistic || expiredSec > uint32(f.args.StaleTTL) {
		return false
	}
	return f.args.StaleMinTTL < 0 || origTTL > uint32(f.args.StaleMinTTL)
}

// doRefresh re-runs the next chain in the background and stores the result.
// Concurrent refreshes of the same key are merged.
func (f *adgCachePlugin) doRefresh(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	select {
	case <-f.prefetchCtx.Done():
		return
	default:
	}

	go func() {
		_, _, _ = f.prefetchSF.Do(key, func() (interface{}, error) {
			pCtx, cancel := context.WithTimeout(f.prefetchCtx, defaultPrefetchTimeout)
			defer cancel()
			f.metrics.refreshTotal.Inc()

			lazyQCtx := qCtx.Copy()
			lazyQCtx.SetResponse(nil)
			err := executable_seq.ExecChainNode(pCtx, lazyQCtx, next)
			if err != nil {
				f.metrics.refreshFailedTotal.Inc()
				f.L().Debug("adg_cache: refresh failed", qCtx.InfoField(), zap.Error(err))
				return nil, nil
			}

			r := lazyQCtx.R()
			if r != nil {
				if storeErr := f.tryStore(key, r); storeErr != nil {
					f.L().Debug("adg_cache: refresh store failed", qCtx.InfoField(), zap.Error(storeErr))
				}
			}
			return nil, nil
		})
	}()
}

func (f *adgCachePlugin) tryStore(key string, r *dns.Msg) error {
	if r.Rcode != dns.RcodeSuccess || r.Truncated {
		return nil
	}

	minTTL := dnsutils.GetMinimalTTL(r)
	if minTTL == 0 {
		return nil
	}

	expiry := uint32(time.Now().Unix()) + minTTL

	packed, err := r.Pack()
	if err != nil {
		return fmt.Errorf("pack response: %w", err)
	}

	if len(packed) > 0xFFFF {
		return fmt.Errorf("packed msg too large: %d bytes", len(packed))
	}

	val := packCacheValue(expiry, packed)
	f.items.Set([]byte(key), val)
	return nil
}

func packCacheValue(expiry uint32, packed []byte) []byte {
	val := make([]byte, 6+len(packed))
	binary.BigEndian.PutUint32(val[0:4], expiry)
	binary.BigEndian.PutUint16(val[4:6], uint16(len(packed)))
	copy(val[6:], packed)
	return val
}

func unpackCacheValue(val []byte) (msg *dns.Msg, expiry uint32, err error) {
	if len(val) < 6 {
		return nil, 0, fmt.Errorf("cache value too short: %d bytes", len(val))
	}

	expiry = binary.BigEndian.Uint32(val[0:4])
	msgLen := binary.BigEndian.Uint16(val[4:6])

	if int(msgLen) > len(val)-6 {
		return nil, 0, fmt.Errorf("cache value length mismatch: header says %d, actual payload %d",
			msgLen, len(val)-6)
	}

	msg = new(dns.Msg)
	if err := msg.Unpack(val[6 : 6+msgLen]); err != nil {
		return nil, 0, fmt.Errorf("unpack dns msg: %w", err)
	}

	return msg, expiry, nil
}

func isCacheable(q *dns.Msg) bool {
	if len(q.Question) != 1 || len(q.Answer) != 0 || len(q.Ns) != 0 {
		return false
	}
	// Allow only OPT (EDNS0) pseudo-record in Extra; reject TSIG, etc.
	for _, e := range q.Extra {
		if e.Header().Rrtype != dns.TypeOPT {
			return false
		}
	}
	return true
}

func (f *adgCachePlugin) Close() error {
	f.prefetchCancel()
	f.items.Clear()
	return nil
}
