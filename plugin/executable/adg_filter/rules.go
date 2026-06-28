package adg_filter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
)

const DefaultRuleBufSize = 1024

// DedupRules deduplicates actual filtering rules across multiple byte sources.
// Comments (!, #) and empty lines are stripped.
func DedupRules(sources ...[]byte) []byte {
	total := 0
	for _, s := range sources {
		total += len(s)
	}
	buf := bytes.NewBuffer(make([]byte, 0, total*3/4))
	seen := make(map[string]struct{}, total/64)

	for _, src := range sources {
		for _, line := range bytes.Split(src, []byte{'\n'}) {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) == 0 || trimmed[0] == '!' || trimmed[0] == '#' {
				continue
			}
			key := string(trimmed)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			buf.Write(trimmed)
			buf.WriteByte('\n')
		}
	}

	return buf.Bytes()
}

// extractDomains returns unique domain strings from deduplicated rules.
func extractDomains(rules []byte) []string {
	seen := make(map[string]struct{}, 100000)
	var domains []string
	for _, line := range bytes.Split(rules, []byte{'\n'}) {
		d, ok := extractDomainFromRule(string(bytes.TrimSpace(line)))
		if !ok {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}
	return domains
}

// loadOrRebuildDomains returns domain list bytes (one domain per line) from
// cache or by downloading local files / remote URLs.
func (f *adgFilter) loadOrRebuildDomains(
	lists []FilterListConfig,
	cacheBaseName string,
) ([]byte, error) {
	// Try cache first.
	if f.args.CacheDir != "" {
		if data, err := f.loadDomainCache(cacheBaseName); err == nil {
			f.L().Info("domain cache loaded",
				zap.String("file", cacheBaseName),
				zap.Int("bytes", len(data)),
			)
			return data, nil
		}
	}

	sources := make([][]byte, 0, 1+len(lists))
	for _, uc := range lists {
		var data []byte
		var err error
		if uc.URL == "" {
			f.L().Warn("filter list entry has no url, skipping", zap.Int("id", uc.ID))
			continue
		}
		if strings.HasPrefix(uc.URL, "file://") {
			path := strings.TrimPrefix(uc.URL, "file://")
			data, err = os.ReadFile(path)
			if err != nil {
				f.L().Warn("failed to read local filter file, skipping",
					zap.Int("id", uc.ID),
					zap.String("path", path),
					zap.Error(err),
				)
				continue
			}
			f.L().Info("local filter file loaded",
				zap.Int("id", uc.ID),
				zap.String("path", path),
				zap.Int("bytes", len(data)),
			)
		} else {
			data, err = f.downloadURL(uc.URL, uc.ID)
			if err != nil {
				f.L().Warn("failed to download filter list, skipping",
					zap.Int("id", uc.ID),
					zap.String("url", uc.URL),
					zap.String("name", uc.Name),
					zap.Error(err),
				)
				continue
			}
			f.L().Info("filter list loaded",
				zap.Int("id", uc.ID),
				zap.Int("bytes", len(data)),
			)
		}
		sources = append(sources, data)
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("no sources available for %s", cacheBaseName)
	}

	deduped := DedupRules(sources...)
	domains := extractDomains(deduped)
	f.L().Info("domain extraction done",
		zap.Int("rule_count", len(domains)),
	)

	data := []byte(strings.Join(domains, "\n"))

	if f.args.CacheDir != "" {
		if err := f.cacheDomainList(cacheBaseName, data); err != nil {
			f.L().Warn("failed to cache domain list", zap.Error(err))
		}
	}

	return data, nil
}

// ── parser funcs for DynamicMatcher ───────────────────────────────

// domainTextParser parses plain text (one domain per line) into a MixMatcher.
func domainTextParser(b []byte) (domain.Matcher[struct{}], error) {
	m := domain.NewDomainMixMatcher()
	if err := domain.LoadFromTextReader[struct{}](m, bytes.NewReader(b), nil); err != nil {
		return nil, err
	}
	return m, nil
}

// ── domain cache helpers ──────────────────────────────────────────

func (f *adgFilter) cacheDomainList(baseName string, data []byte) error {
	if err := os.MkdirAll(f.args.CacheDir, 0755); err != nil {
		return fmt.Errorf("mkdir cache: %w", err)
	}
	path := filepath.Join(f.args.CacheDir, baseName)
	return os.WriteFile(path, data, 0644)
}

func (f *adgFilter) loadDomainCache(baseName string) ([]byte, error) {
	path := filepath.Join(f.args.CacheDir, baseName)
	if !f.isCacheValid(path) {
		return nil, fmt.Errorf("cache expired or missing: %s", baseName)
	}
	return os.ReadFile(path)
}

// ── rule parsing ──────────────────────────────────────────────────

func extractDomainFromRule(line string) (string, bool) {
	if line == "" {
		return "", false
	}
	if strings.HasPrefix(line, "@@") {
		return "", false
	}
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return "", false
	}

	// ||domain.com^… (AdBlock domain pattern)
	if strings.HasPrefix(line, "||") {
		rest := line[2:]
		idx := strings.IndexAny(rest, "^$/")
		if idx < 0 {
			idx = len(rest)
		}
		return strings.ToLower(rest[:idx]), true
	}

	// IP domain (hosts format)
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if net.ParseIP(fields[0]) != nil {
			return strings.ToLower(fields[1]), true
		}
	}

	// Plain domain or keyword.
	if strings.ContainsAny(line, "*[]{}()/^$@") {
		return "", false
	}
	if len(line) < 3 || len(line) > 253 {
		return "", false
	}
	if strings.Contains(line, " ") {
		return "", false
	}
	return strings.ToLower(line), true
}

// ── download helpers ─────────────────────────────────────────────

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
	f.L().Info("downloading filter list", zap.Int("id", id), zap.String("url", rawURL))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return f.tryCache(path, fmt.Errorf("create request: %w", err))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return f.tryCache(path, fmt.Errorf("download: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return f.tryCache(path, fmt.Errorf("status %d", resp.StatusCode))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return f.tryCache(path, fmt.Errorf("read body: %w", err))
	}

	if path != "" {
		if err := f.writeCacheFile(path, data); err != nil {
			f.L().Warn("failed to cache filter file", zap.Int("id", id), zap.Error(err))
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

// ── cache helpers ────────────────────────────────────────────────

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
		return fmt.Errorf("mkdir cache: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
