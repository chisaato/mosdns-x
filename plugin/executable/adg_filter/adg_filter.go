package adg_filter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "adg_filter"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*adgFilter)(nil)

// FilterListConfig 定义一个过滤列表源（URL）。
type FilterListConfig struct {
	URL  string `yaml:"url"`
	Name string `yaml:"name"`
	ID   int    `yaml:"id"`
	// 占位符,兼容 AdGuard Home 格式,暂未使用
	// 不应被删除
	Enabled *bool `yaml:"enabled,omitempty"`
}

type Args struct {
	// 拦截列表：URL 源
	BlockLists []FilterListConfig `yaml:"block_lists"`
	// 拦截列表：用户手工填入的内联规则（AdBlock 语法或纯域名）
	BlockInline []string `yaml:"block_inline"`

	// 白名单：URL 源
	AllowLists []FilterListConfig `yaml:"allow_lists"`
	// 白名单：用户手工填入的内联规则
	AllowInline []string `yaml:"allow_inline"`

	BlockMode      string `yaml:"block_mode"`      // "nxdomain" (default), "refused", "zero_ip", "custom_ip"
	BlockingIPv4   string `yaml:"blocking_ipv4"`   // custom IP for A (default "0.0.0.0")
	BlockingIPv6   string `yaml:"blocking_ipv6"`   // custom IP for AAAA (default "::")
	UpdateInterval int    `yaml:"update_interval"` // seconds, default 86400 (24h)
	CacheDir       string `yaml:"cache_dir"`       // 本地磁盘缓存目录（可选），启用后过滤列表会缓存到本地，避免重启后重新下载
}

type adgFilter struct {
	*coremain.BP
	args *Args

	blockEngine  *urlfilter.DNSEngine
	allowEngine  *urlfilter.DNSEngine
	blockingIPv4 netip.Addr
	blockingIPv6 netip.Addr

	mu     sync.RWMutex
	cancel context.CancelFunc
	done   chan struct{}
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newAdgFilter(bp, args.(*Args))
}

func newAdgFilter(bp *coremain.BP, args *Args) (*adgFilter, error) {
	// defaults
	if args.BlockMode == "" {
		args.BlockMode = "nxdomain"
	}
	if args.BlockingIPv4 == "" {
		args.BlockingIPv4 = "0.0.0.0"
	}
	if args.BlockingIPv6 == "" {
		args.BlockingIPv6 = "::"
	}
	if args.UpdateInterval <= 0 {
		args.UpdateInterval = 86400
	}

	ipv4, err := netip.ParseAddr(args.BlockingIPv4)
	if err != nil {
		return nil, fmt.Errorf("invalid blocking_ipv4 %s: %w", args.BlockingIPv4, err)
	}
	if !ipv4.Is4() {
		return nil, fmt.Errorf("blocking_ipv4 %s is not a valid IPv4 address", args.BlockingIPv4)
	}
	ipv6, err := netip.ParseAddr(args.BlockingIPv6)
	if err != nil {
		return nil, fmt.Errorf("invalid blocking_ipv6 %s: %w", args.BlockingIPv6, err)
	}
	if !ipv6.Is6() {
		return nil, fmt.Errorf("blocking_ipv6 %s is not a valid IPv6 address", args.BlockingIPv6)
	}

	f := &adgFilter{
		BP:           bp,
		args:         args,
		blockingIPv4: ipv4,
		blockingIPv6: ipv6,
	}

	// Phase 1: instant engine from cache only (no HTTP).
	f.blockEngine = f.buildEngineCached(args.BlockLists, args.BlockInline, 1)
	if len(args.AllowLists) > 0 || len(args.AllowInline) > 0 {
		f.allowEngine = f.buildEngineCached(args.AllowLists, args.AllowInline, 1000000)
	}

	bp.L().Info("adg_filter initialized",
		zap.Int("block_rules", int(f.blockEngine.RulesCount())),
		zap.Bool("allowlist_enabled", f.allowEngine != nil),
		zap.String("block_mode", args.BlockMode),
	)

	// Phase 2: background full download + periodic updates (never blocks startup).
	if args.CacheDir != "" {
		activeIDs := make([]int, 0, len(args.BlockLists)+len(args.AllowLists))
		for _, l := range args.BlockLists {
			activeIDs = append(activeIDs, l.ID)
		}
		for _, l := range args.AllowLists {
			activeIDs = append(activeIDs, l.ID)
		}
		f.cleanOrphanCaches(activeIDs)
	}

	if len(args.BlockLists) > 0 || len(args.AllowLists) > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		f.cancel = cancel
		f.done = make(chan struct{})
		go f.runBackground(ctx)
	}

	return f, nil
}

// buildEngineCached builds a urlfilter.DNSEngine from cache only (no HTTP).
// URL lists missing from cache are silently skipped so startup never blocks.
func (f *adgFilter) buildEngineCached(
	urls []FilterListConfig,
	inline []string,
	baseID rules.ListID,
) *urlfilter.DNSEngine {
	var lists []filterlist.Interface
	id := baseID

	if len(inline) > 0 {
		text := strings.Join(inline, "\n")
		s := filterlist.NewString(&filterlist.StringConfig{
			ID:             id,
			RulesText:      text,
			IgnoreCosmetic: true,
		})
		lists = append(lists, s)
		id++
	}

	for _, uc := range urls {
		path := f.cachePath(uc.ID)
		if path == "" {
			continue
		}
		data, err := f.readCacheFile(path)
		if err != nil {
			f.L().Debug("no cache for filter list, will download later",
				zap.Int("id", uc.ID),
				zap.String("name", uc.Name),
			)
			continue
		}
		b := filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             id,
			RulesText:      data,
			IgnoreCosmetic: true,
		})
		lists = append(lists, b)
		f.L().Info("loaded filter list from cache",
			zap.Int("id", uc.ID),
			zap.String("name", uc.Name),
			zap.Int("bytes", len(data)),
		)
		id++
	}

	if len(lists) == 0 {
		storage, _ := filterlist.NewRuleStorage(nil)
		return urlfilter.NewDNSEngine(storage)
	}

	storage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		for _, l := range lists {
			_ = l.Close()
		}
		storage, _ := filterlist.NewRuleStorage(nil)
		return urlfilter.NewDNSEngine(storage)
	}
	return urlfilter.NewDNSEngine(storage)
}

// buildEngine creates a urlfilter.DNSEngine from URL lists and inline rules.
// It always re-downloads URL lists (no cache path). baseID is the starting ListID prefix.
func (f *adgFilter) buildEngine(
	urls []FilterListConfig,
	inline []string,
	baseID rules.ListID,
) (*urlfilter.DNSEngine, error) {
	var lists []filterlist.Interface
	id := baseID

	// Inline rules (user-manual custom rules).
	if len(inline) > 0 {
		text := strings.Join(inline, "\n")
		s := filterlist.NewString(&filterlist.StringConfig{
			ID:             id,
			RulesText:      text,
			IgnoreCosmetic: true,
		})
		lists = append(lists, s)
		id++
	}

	// URL-based filter lists (downloaded).
	for _, uc := range urls {
		data, err := f.downloadURL(uc.URL, uc.ID)
		if err != nil {
			f.L().Warn("failed to download filter list, skipping",
				zap.Int("id", uc.ID),
				zap.String("url", uc.URL),
				zap.String("name", uc.Name),
				zap.Error(err),
			)
			continue
		}
		b := filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             id,
			RulesText:      data,
			IgnoreCosmetic: true,
		})
		lists = append(lists, b)
		f.L().Info("filter list loaded",
			zap.Int("id", uc.ID),
			zap.String("name", uc.Name),
			zap.Int("bytes", len(data)),
		)
		id++
	}

	if len(lists) == 0 {
		storage, err := filterlist.NewRuleStorage(nil)
		if err != nil {
			return nil, err
		}
		return urlfilter.NewDNSEngine(storage), nil
	}

	storage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		for _, l := range lists {
			_ = l.Close()
		}
		return nil, fmt.Errorf("failed to create rule storage: %w", err)
	}

	return urlfilter.NewDNSEngine(storage), nil
}

func (f *adgFilter) cachePath(id int) string {
	if f.args.CacheDir == "" {
		return ""
	}
	return filepath.Join(f.args.CacheDir, fmt.Sprintf("%d.txt", id))
}

func (f *adgFilter) isCacheValid(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	interval := time.Duration(f.args.UpdateInterval) * time.Second
	return st.ModTime().Add(interval).After(time.Now())
}

func (f *adgFilter) readCacheFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (f *adgFilter) writeCacheFile(path string, data []byte) error {
	if err := os.MkdirAll(f.args.CacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (f *adgFilter) cleanOrphanCaches(activeIDs []int) {
	if f.args.CacheDir == "" {
		return
	}
	activeSet := make(map[string]struct{}, len(activeIDs))
	for _, id := range activeIDs {
		activeSet[f.cachePath(id)] = struct{}{}
	}
	entries, err := os.ReadDir(f.args.CacheDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(f.args.CacheDir, e.Name())
		if _, keep := activeSet[p]; !keep {
			if err := os.Remove(p); err == nil {
				f.L().Debug("removed orphan cache file", zap.String("file", e.Name()))
			}
		}
	}
}

// downloadURL returns cached data if still valid, otherwise downloads remote.
func (f *adgFilter) downloadURL(rawURL string, id int) ([]byte, error) {
	path := f.cachePath(id)
	if path != "" && f.isCacheValid(path) {
		data, err := f.readCacheFile(path)
		if err == nil {
			f.L().Info("loaded filter list from cache",
				zap.Int("id", id),
				zap.String("url", rawURL),
			)
			return data, nil
		}
	}
	return f.downloadAndCache(rawURL, path, id)
}

func (f *adgFilter) downloadAndCache(rawURL, path string, id int) ([]byte, error) {
	f.L().Info("downloading filter list",
		zap.Int("id", id),
		zap.String("url", rawURL),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return f.tryCache(path, fmt.Errorf("failed to create request: %w", err))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return f.tryCache(path, fmt.Errorf("failed to download: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return f.tryCache(path, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return f.tryCache(path, fmt.Errorf("failed to read response body: %w", err))
	}

	if path != "" {
		if err := f.writeCacheFile(path, data); err != nil {
			f.L().Warn("failed to write filter cache file",
				zap.Int("id", id),
				zap.Error(err),
			)
		}
	}
	return data, nil
}

func (f *adgFilter) tryCache(path string, origErr error) ([]byte, error) {
	if path == "" {
		return nil, origErr
	}
	data, err := f.readCacheFile(path)
	if err != nil {
		return nil, origErr
	}
	f.L().Info("using cached filter list (download failed)",
		zap.String("file", filepath.Base(path)),
	)
	return data, nil
}

// runBackground does an initial full download then enters the periodic update
// loop. Never blocks startup — goroutine launched from Init.
func (f *adgFilter) runBackground(ctx context.Context) {
	defer close(f.done)

	f.L().Info("adg_filter: starting background filter update")
	f.updateEngines()

	ticker := time.NewTicker(time.Duration(f.args.UpdateInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.updateEngines()
		}
	}
}

// updateEngines atomically swaps blockEngine and allowEngine after re-download.
func (f *adgFilter) updateEngines() {
	// Update block engine.
	if len(f.args.BlockLists) > 0 {
		newEngine, err := f.buildEngine(f.args.BlockLists, f.args.BlockInline, 1)
		if err != nil {
			f.L().Warn("failed to update block engine, keeping old engine", zap.Error(err))
		} else {
			f.mu.Lock()
			f.blockEngine = newEngine
			f.mu.Unlock()
			f.L().Info("block engine updated", zap.Int("rules", int(newEngine.RulesCount())))
		}
	}

	// Update allow engine.
	if len(f.args.AllowLists) > 0 {
		newEngine, err := f.buildEngine(f.args.AllowLists, f.args.AllowInline, 1000000)
		if err != nil {
			f.L().Warn("failed to update allow engine, keeping old engine", zap.Error(err))
		} else {
			f.mu.Lock()
			f.allowEngine = newEngine
			f.mu.Unlock()
			f.L().Info("allow engine updated", zap.Int("rules", int(newEngine.RulesCount())))
		}
	}
}

// Exec implements coremain.ExecutablePlugin.
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

	req := &urlfilter.DNSRequest{
		Hostname: hostname,
		DNSType:  rules.RRType(qtype),
	}

	f.mu.RLock()
	allowEngine := f.allowEngine
	blockEngine := f.blockEngine
	f.mu.RUnlock()

	// Check allowlist first — if matched, pass through.
	if allowEngine != nil {
		if _, matched := allowEngine.MatchRequest(req); matched {
			f.L().Info("adg_filter: allowlist hit, pass through",
				zap.String("host", hostname),
				zap.String("qtype", dns.Type(qtype).String()),
			)
			return executable_seq.ExecChainNode(ctx, qCtx, next)
		}
	}

	// Check blocklist — if matched, block.
	if _, matched := blockEngine.MatchRequest(req); matched {
		f.L().Info("adg_filter: blocklist hit, blocked",
			zap.String("host", hostname),
			zap.String("qtype", dns.Type(qtype).String()),
		)
		f.applyBlock(qCtx, q, qtype)
		return nil
	}

	f.L().Debug("adg_filter: no match, pass through",
		zap.String("host", hostname),
		zap.String("qtype", dns.Type(qtype).String()),
	)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

// applyBlock generates a blocking response based on BlockMode.
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

// Shutdown stops the background update goroutine.
func (f *adgFilter) Shutdown() error {
	if f.cancel != nil {
		f.cancel()
		if f.done != nil {
			<-f.done
		}
	}
	return nil
}
