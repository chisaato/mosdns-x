package tools

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/mlog"
	adg "github.com/pmkol/mosdns-x/plugin/executable/adg_filter"
	"github.com/pmkol/mosdns-x/pkg/matcher/v2data"
)

func newCompileAdsCmd() *cobra.Command {
	var (
		configPath string
		outputPath string
		filterTag  string
		geositeTag string
	)

	c := &cobra.Command{
		Use:   "compile-ads -c mosdns.yaml -o ads.dat",
		Args:  cobra.NoArgs,
		Short: "Compile adg_filter block lists from mosdns config into geosite dat.",
		Long: `Reads a mosdns YAML config, finds adg_filter plugins, downloads their
block_lists, deduplicates, and compiles to a geosite .dat binary.

Flags:
  -c  mosdns config YAML (required)
  -o  output .dat file (required)
  -f  adg_filter plugin tag (default: first adg_filter in config)
  -t  geosite country-code tag (default: "ads")
`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := runCompileAds(configPath, outputPath, filterTag, geositeTag); err != nil {
				mlog.S().Fatal(err)
			}
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVarP(&configPath, "config", "c", "", "mosdns config YAML path")
	c.Flags().StringVarP(&outputPath, "output", "o", "", "output .dat file")
	c.Flags().StringVarP(&filterTag, "filter-tag", "f", "", "adg_filter plugin tag (default: first)")
	c.Flags().StringVarP(&geositeTag, "tag", "t", "ads", "geosite tag name")
	c.MarkFlagRequired("config")
	c.MarkFlagRequired("output")
	return c
}

func runCompileAds(configPath, outputPath, pluginTag, geositeTag string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	mosdnsCfg := new(coremain.Config)
	if err := yaml.Unmarshal(raw, mosdnsCfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	var pcfg *coremain.PluginConfig
	for i := range mosdnsCfg.Plugins {
		p := &mosdnsCfg.Plugins[i]
		if p.Type != adg.PluginType {
			continue
		}
		if pluginTag != "" && p.Tag != pluginTag {
			continue
		}
		pcfg = p
		break
	}
	if pcfg == nil {
		return fmt.Errorf("no adg_filter plugin (tag=%q) in config", pluginTag)
	}
	mlog.S().Infof("using plugin tag=%q", pcfg.Tag)

	argsMap, ok := pcfg.Args.(map[string]interface{})
	if !ok {
		return fmt.Errorf("plugin %q args is not a map", pcfg.Tag)
	}
	argsYAML, _ := yaml.Marshal(argsMap)

	type plugArgs struct {
		BlockLists  []adg.FilterListConfig `yaml:"block_lists"`
		CompiledTag string                 `yaml:"compiled_tag"`
	}
	var a plugArgs
	if err := yaml.Unmarshal(argsYAML, &a); err != nil {
		return fmt.Errorf("decode plugin args: %w", err)
	}
	if a.CompiledTag != "" {
		geositeTag = a.CompiledTag
	}

	client := &http.Client{Timeout: 60 * time.Second}
	var sources [][]byte

	for _, l := range a.BlockLists {
		if strings.HasPrefix(l.URL, "file://") {
			path := strings.TrimPrefix(l.URL, "file://")
			body, err := os.ReadFile(path)
			if err != nil {
				mlog.S().Warnf("  read file %s: %v", path, err)
				continue
			}
			sources = append(sources, body)
			mlog.S().Infof("loaded local %s: %d bytes", path, len(body))
			continue
		}
		if l.URL == "" {
			mlog.S().Warnf("  skip entry (no url)")
			continue
		}
		mlog.S().Infof("downloading %s", l.URL)
		resp, err := client.Get(l.URL)
		if err != nil {
			mlog.S().Warnf("  skip: %v", err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			mlog.S().Warnf("  read error: %v", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			mlog.S().Warnf("  status %d", resp.StatusCode)
			continue
		}
		sources = append(sources, body)
		mlog.S().Infof("  %d bytes", len(body))
	}

	if len(sources) == 0 {
		return fmt.Errorf("no sources downloaded")
	}

	deduped := adg.DedupRules(sources...)
	mlog.S().Infof("deduplicated: %d bytes", len(deduped))

	domains := extractDomainsForCLI(deduped)
	mlog.S().Infof("extracted %d unique domains", len(domains))

	return writeGeositeFile(outputPath, geositeTag, domains)
}

func extractDomainsForCLI(rules []byte) []string {
	seen := make(map[string]struct{}, 100000)
	var out []string
	for _, raw := range strings.Split(string(rules), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		d, ok := cliExtractDomain(line)
		if !ok {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func cliExtractDomain(line string) (string, bool) {
	if line == "" || line[0] == '#' || line[0] == '!' {
		return "", false
	}
	if strings.HasPrefix(line, "@@") {
		return "", false
	}
	if strings.HasPrefix(line, "||") {
		rest := line[2:]
		idx := strings.IndexAny(rest, "^$/")
		if idx < 0 {
			idx = len(rest)
		}
		return strings.ToLower(rest[:idx]), true
	}
	if idx := strings.IndexByte(line, ' '); idx > 0 {
		first := strings.TrimSpace(line[:idx])
		if len(first) > 0 && first[0] >= '0' && first[0] <= '9' {
			return strings.ToLower(strings.TrimSpace(line[idx+1:])), true
		}
	}
	if strings.ContainsAny(line, "*[]{}()/^$@") {
		return "", false
	}
	if len(line) < 3 || len(line) > 253 {
		return "", false
	}
	if !strings.Contains(line, ".") {
		return "", false
	}
	return strings.ToLower(line), true
}

func writeGeositeFile(path, tag string, domains []string) error {
	entries := make([]*v2data.Domain, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, &v2data.Domain{Type: v2data.Domain_Domain, Value: d})
	}
	blob, err := proto.Marshal(&v2data.GeoSiteList{
		Entry: []*v2data.GeoSite{{CountryCode: tag, Domain: entries}},
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, blob, 0644)
}
