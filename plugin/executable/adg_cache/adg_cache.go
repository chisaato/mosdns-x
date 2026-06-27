package adg_cache

import (
	"context"
	"encoding/binary"
	"fmt"
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
	Optimistic bool `yaml:"optimistic"`
}

type adgCachePlugin struct {
	*coremain.BP
	args *Args

	items          glcache.Cache
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
	if !args.Optimistic && args.StaleTTL > 0 {
		args.Optimistic = true
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &adgCachePlugin{
		BP:   bp,
		args: args,
		items: glcache.New(glcache.Config{
			MaxSize:   uint(args.Size),
			EnableLRU: true,
		}),
		prefetchCtx:    ctx,
		prefetchCancel: cancel,
	}
	return p, nil
}

func (f *adgCachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()

	if !isCacheable(q) {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	key, err := dnsutils.GetMsgKey(q, 0)
	if err != nil {
		f.L().Warn("adg_cache: get msg key", qCtx.InfoField(), zap.Error(err))
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	cached := f.items.Get([]byte(key))
	if cached != nil {
		msg, expiry, err := unpackCacheValue(cached)
		if err != nil {
			f.L().Warn("adg_cache: unpack cached value", qCtx.InfoField(), zap.Error(err))
			return executable_seq.ExecChainNode(ctx, qCtx, next)
		}

		now := uint32(time.Now().Unix())

		// Fresh entry (not expired): serve directly.
		if now < expiry {
			elapsed := expiry - now
			origTTL := dnsutils.GetMinimalTTL(msg)
			if elapsed < origTTL {
				dnsutils.SubtractTTL(msg, origTTL-elapsed)
			}
			msg.Id = q.Id
			qCtx.SetResponse(msg)
			f.L().Debug("adg_cache: fresh hit", qCtx.InfoField())
			return nil
		}

		// Expired entry.
		expiredSec := now - expiry

		// If optimistic is on and still within StaleTTL, serve stale.
		if f.args.Optimistic && expiredSec <= uint32(f.args.StaleTTL) {
			dnsutils.SetTTL(msg, uint32(f.args.OptimisticTTL))
			msg.Id = q.Id
			qCtx.SetResponse(msg)
			f.L().Debug("adg_cache: stale hit",
				qCtx.InfoField(),
				zap.Uint32("expired_sec", expiredSec),
			)

			// Trigger prefetch if enabled and within prefetch window.
			if f.args.Prefetch && expiredSec <= uint32(f.args.PrefetchTTL) {
				f.doPrefetch(key, qCtx, next)
			}
			return nil
		}

		// Not optimistic or beyond StaleTTL: treat as miss.
		f.L().Debug("adg_cache: miss (expired beyond stale)", qCtx.InfoField())
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

func (f *adgCachePlugin) doPrefetch(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	select {
	case <-f.prefetchCtx.Done():
		return
	default:
	}

	go func() {
		_, _, _ = f.prefetchSF.Do(key, func() (interface{}, error) {
			defer f.prefetchSF.Forget(key)

			pCtx, cancel := context.WithTimeout(f.prefetchCtx, defaultPrefetchTimeout)
			defer cancel()

			lazyQCtx := qCtx.Copy()
			err := executable_seq.ExecChainNode(pCtx, lazyQCtx, next)
			if err != nil {
				f.L().Debug("adg_cache: prefetch failed", qCtx.InfoField(), zap.Error(err))
				return nil, nil
			}

			r := lazyQCtx.R()
			if r != nil {
				if storeErr := f.tryStore(key, r); storeErr != nil {
					f.L().Debug("adg_cache: prefetch store failed", qCtx.InfoField(), zap.Error(storeErr))
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
	return len(q.Question) == 1 && len(q.Answer) == 0 && len(q.Ns) == 0 && len(q.Extra) == 0
}

func (f *adgCachePlugin) Close() error {
	f.prefetchCancel()
	f.items.Clear()
	return nil
}
