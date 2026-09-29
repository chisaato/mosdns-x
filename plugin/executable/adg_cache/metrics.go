package adg_cache

import (
	"encoding/binary"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type cacheMetrics struct {
	queryTotal         prometheus.Counter
	hitTotal           prometheus.Counter
	staleHitTotal      prometheus.Counter
	refreshTotal       prometheus.Counter
	refreshFailedTotal prometheus.Counter
	evictedTotal       prometheus.Counter
	evictedLiveTotal   prometheus.Counter
}

func newCacheMetrics() *cacheMetrics {
	counter := func(name, help string) prometheus.Counter {
		return prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	}
	return &cacheMetrics{
		queryTotal:         counter("query_total", "Cacheable queries looked up in the cache"),
		hitTotal:           counter("hit_total", "Queries answered by a fresh entry"),
		staleHitTotal:      counter("stale_hit_total", "Queries answered by an expired entry"),
		refreshTotal:       counter("refresh_total", "Background refreshes run (prefetch and stale)"),
		refreshFailedTotal: counter("refresh_failed_total", "Background refreshes that returned an error"),
		evictedTotal:       counter("evicted_total", "Entries evicted by LRU to make room"),
		evictedLiveTotal:   counter("evicted_live_total", "Evicted entries that could still be served, fresh or stale"),
	}
}

// onEvict is the LRU eviction callback. An entry evicted while it could
// still be served (before expiry + stale_ttl) is a hit lost to cache size.
func (f *adgCachePlugin) onEvict(_, val []byte) {
	f.metrics.evictedTotal.Inc()
	if len(val) < 4 {
		return
	}
	expiry := binary.BigEndian.Uint32(val[0:4])
	if uint32(time.Now().Unix()) <= expiry+uint32(f.args.StaleTTL) {
		f.metrics.evictedLiveTotal.Inc()
	}
}

// registerMetrics exports the counters plus entry count and byte size under
// mosdns_plugin_<tag>_ on the api.http /metrics endpoint.
func (f *adgCachePlugin) registerMetrics() error {
	if f.M() == nil { // not running inside mosdns, e.g. in tests
		return nil
	}
	m := f.metrics
	entries := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "entries",
		Help: "Entries in the cache",
	}, func() float64 { return float64(f.items.Stats().Count) })
	size := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "size_bytes",
		Help: "Bytes used by keys and values, bounded by size",
	}, func() float64 { return float64(f.items.Stats().Size) })
	maxSize := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "max_size_bytes",
		Help: "Configured size limit in bytes",
	}, func() float64 { return float64(f.args.Size) })

	for _, c := range []prometheus.Collector{
		m.queryTotal, m.hitTotal, m.staleHitTotal, m.refreshTotal, m.refreshFailedTotal,
		m.evictedTotal, m.evictedLiveTotal, entries, size, maxSize,
	} {
		if err := f.GetMetricsReg().Register(c); err != nil {
			return err
		}
	}
	return nil
}
