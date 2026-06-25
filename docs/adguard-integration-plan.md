# mosdns-x + AdGuard 核心技术融合方案

## 动机

现有架构：**dnsdist (MAC分流) → AdGuard DoH (过滤)** 两跳，RSS ~260 MB，C++ 维护成本高。
目标：**mosdns 流水线 + AdGuard 核心技术 (urlfilter + dnsproxy upstream + golibs cache)** 单进程 Go 方案。

## 架构图

```
                         mosdns 流水线
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  dnsdist 现有能力              AdGuard 嫁接核心                │
    │  ──────────────────           ──────────────────              │
    │  mac_extract (EDNS 65001)     adg_filter (urlfilter engine)  │
    │  query_matcher (MAC/domain)   adg_cache  (golibs/cache)      │
    │  fast_forward (upstream)      forward    (dnsproxy/upstream) │
    │  sequence / if / fallback                                    │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
                                ↓
                       upstream (DoH / DoT / DoQ)
```

## 依赖分析（全部公开可引，无 internal 问题）

| 插件 | Go 依赖 | 是否 public | 来源 |
|------|---------|:----------:|------|
| `adg_filter` | `github.com/AdguardTeam/urlfilter` | ✅ | 独立 module，可直接 go get |
| `adg_cache` | `github.com/AdguardTeam/golibs/cache` | ✅ | 字节限制 LRU cache，dnsproxy 底层也在用 |
| `forward` | `github.com/AdguardTeam/dnsproxy/upstream` | ✅ | `AddressToUpstream()` `ExchangeParallel()` 全部导出 |
| `mac_extract` | mosdns 现有 (pkg/matcher/macaddr) | ✅ | 已实现 |
| `dnstap_log` | `github.com/dnstap/golang-dnstap` | ✅ | 独立 module |

## 插件设计

### 1. `forward` — 从 git 历史恢复的 AdGuard 转发插件

**历史**：`plugin/executable/forward/forward.go` 在 commit `d253ed8` 被删除，之前直接使用 `github.com/AdguardTeam/dnsproxy/upstream`。

**核心逻辑**（约 60 行）：

```go
import dnsproxy_upstream "github.com/AdguardTeam/dnsproxy/upstream"

type Args struct {
    UpstreamConfig []UpstreamConfig `yaml:"upstream"`
    Timeout        int              `yaml:"timeout"`
}

func (f *forwardPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
    q := qCtx.Q().Copy()
    r, _, err := upstream.ExchangeParallel(f.upstreams, q)  // ← dnsproxy 核心
    if err != nil {
        return err
    }
    qCtx.SetResponse(r)
    return executable_seq.ExecChainNode(ctx, qCtx, next)
}
```

**相对于 `fast_forward` 的优势**：
- 原生支持 DoH / DoT / DoQ / DNSCrypt 全部协议
- `ExchangeParallel` 已处理并发、超时、fallback
- 更少的自维护代码

### 2. `adg_cache` — 字节限制 LRU 缓存

**后端**：`github.com/AdguardTeam/golibs/cache`（字节限制 LRU，dnsproxy 同款）

```go
import glcache "github.com/AdguardTeam/golibs/cache"

type Args struct {
    SizeBytes     int  `yaml:"size_bytes"`      // 字节限制（dnsproxy 默认 64KB，推荐 50MB）
    Prefetch      int  `yaml:"prefetch"`         // 过期前 N 秒异步刷新
    StaleTTL      int  `yaml:"stale_ttl"`        // 过期后还能用多久
    OptimisticTTL int  `yaml:"optimistic_ttl"`   // 乐观缓存默认 TTL
}
```

**与 mosdns 自带 cache 的对比**：

| 特性 | mosdns cache | adg_cache |
|------|:---:|:---:|
| 容量限制 | 条数 (size) | 字节数 (size_bytes) |
| evict 策略 | FIFO/LRU | LRU（golibs/cache） |
| Prefetch | ❌ | ✅ |
| Stale refresh | 固定 lazy_cache_ttl | 可控 |
| 依赖 | mem_cache / Redis | golibs/cache（无额外依赖） |

### 3. `adg_filter` — AdGuard 广告拦截引擎

**引擎**：`github.com/AdguardTeam/urlfilter`（支持 AdBlock 语法 + 纯域名列表）

```go
import "github.com/AdguardTeam/urlfilter"

type Args struct {
    Lists     []string `yaml:"lists"`      // 规则文件路径（支持 .txt 纯域名 + .txt AdBlock 语法）
    BlockMode string   `yaml:"block_mode"` // nxdomain / refused / zero_ip
}
```

**规则来源**：直接复用现有 dnsdist 的 `block-nxdomain.txt`（349k 纯域名），urlfilter.DNSEngine 也支持 AdBlock 语法（`||domain.com^`）。

**内存预期**：urlfilter 的 URL trie 比 SuffixMatchNode 紧凑得多，同样 349k 域名预计 20-30 MB（vs dnsdist 的 60-80 MB）。

### 4. `mac_extract` — 已有

已在 `pkg/matcher/macaddr/` 和 `plugin/matcher/query_matcher/` 中工作正常。通过 `EDNS0_LOCAL` (option 65001) 提取 MAC 地址。

### 5. `dnstap_log` — 可选，后期加

mosdns 已有 `metrics_collector` 插件，加 dnstap 只需把 `query_context.Context` 的 Q/R/ReqMeta 事件写入 framestream。

---

## 完整 YAML 配置案例

```yaml
# mosdns-x 完整配置
log:
  level: info

data_providers:
  - tag: mac_clean
    file:
      path: /etc/mosdns/mac-clean.txt
      auto_reload: 300
  - tag: block_nxdomain
    file:
      path: /etc/dnsdist/lists/block-nxdomain.txt
      auto_reload: 300
  - tag: cn_domains
    file:
      path: /etc/dnsdist/lists/cn.txt
      auto_reload: 300

plugins:
  # ── 匹配器 ──
  - tag: is_clean_mac
    type: query_matcher
    args:
      mac_address:
        - provider: mac_clean

  - tag: is_cn_domain
    type: query_matcher
    args:
      domain:
        - provider: cn_domains

  - tag: is_adult_domain
    type: query_matcher
    args:
      domain:
        - provider: block_adult

  # ── 广告拦截 ──
  - tag: adg_block
    type: adg_filter
    args:
      lists:
        - /etc/dnsdist/lists/block-nxdomain.txt
      block_mode: nxdomain

  # ── 缓存 ──
  - tag: adg_cache
    type: adg_cache
    args:
      size_bytes: 52428800    # 50 MB
      prefetch: 10            # 过期前 10 秒预刷新
      stale_ttl: 300          # 过期后还能用 300 秒
      optimistic_ttl: 30

  # ── 上游 ──
  - tag: self_doh
    type: forward
    args:
      upstream:
        - addr: https://adguard.example.com/dns-query
      timeout: 10

  - tag: self_no_filter
    type: forward
    args:
      upstream:
        - addr: tls://local-dns.lan:853
      timeout: 5

  - tag: cn_upstream
    type: forward
    args:
      upstream:
        - addr: tls://dns.alidns.com
        - addr: https://doh.pub/dns-query
      timeout: 10

  - tag: overseas_upstream
    type: forward
    args:
      upstream:
        - addr: https://dns.adguard.com/dns-query
        - addr: https://cloudflare-dns.com/dns-query
      timeout: 10

  # ── 序列（主干流水线） ──
  - tag: main_sequence
    type: sequence
    args:
      exec:
        # 1. EDNS 65001 MAC 标记
        - if: is_clean_mac
          exec: _plugin_self_no_filter     # 干净 MAC → 不过滤
          else_exec: _plugin_adg_block     # 其他 → 先查广告拦截

        # 2. 广告拦截（非干净 MAC 已经走 adg_block）
        #    命中→NXDOMAIN 短路; 未命中→继续

        # 3. 缓存
        - exec: adg_cache

        # 4. MAC 分流
        - if: is_clean_mac
          exec:
            - if: is_cn_domain
              exec: cn_upstream
              else_exec: overseas_upstream
          else_exec:
            - if: is_cn_domain
              exec: cn_upstream
              else_exec: self_doh

# 预设插件（简化流水线引用）
  - tag: _plugin_self_no_filter
    type: sequence
    args:
      exec:
        - exec: adg_cache
        - exec: self_no_filter

  - tag: _plugin_adg_block
    type: sequence
    args:
      exec:
        - exec: adg_block
        - exec: adg_cache
        - exec: overseas_upstream

servers:
  - exec: main_sequence
    timeout: 10
    listeners:
      - protocol: udp
        addr: :53
      - protocol: tcp
        addr: :53
```

## 实现路线

```
Phase 1 — 核心插件
├── 恢复 forward 插件                (git checkout d253ed8^ + 适配新版 dnsproxy API)
├── 新建 adg_filter 插件             (~200 行, urlfilter.DNSEngine)
├── 新建 adg_cache 插件              (~150 行, golibs/cache)
├── plugin/enabled_plugin.go 加 import
└── go.mod 加三个依赖

Phase 2 — 流水线编排
├── 对照 dnsdist 的 mac.lua / routing.lua 翻译成 YAML 流水线
├── 验证 MAC 分流逻辑
└── 验证广告拦截 + 缓存命中

Phase 3 — 可观测性（可选）
├── 新建 dnstap_log 插件 (~100 行)
└── 或使用 mosdns 现有 metrics_collector
```

## 决策记录

| 日期 | 决定 | 理由 |
|------|------|------|
| 2026-06-26 | 放弃 dnsdist，深改 mosdns-x | 用户擅长 Go，流水线表达力强，EDNS 65001 已有实现 |
| 2026-06-26 | 嫁接 urlfilter 而非自写匹配引擎 | 生产验证的 349k 域名字典匹配，内存更优 |
| 2026-06-26 | 使用 golibs/cache 而非自写 | dnsproxy 同款，字节限制 LRU，零额外维护 |
| 2026-06-26 | 恢复 forward 而非继续改 fast_forward | dnsproxy/upstream 天然支持全部加密协议，代码量更少 |
| 2026-06-26 | 不使用 mosdns 自带 cache | 其条数限制不适应大规模场景，缺少 prefetch/stale refresh |
| 2026-06-26 | 不使用 CoreDNS / Blocky | CoreDNS 插件开发成本高；Blocky conditional 只能映射表，不是流水线 |

## 参考

- `plugin/executable/fast_forward/` — 当前的内联转发实现
- `plugin/executable/cache/cache.go` — mosdns 现有缓存（参考接口设计）
- `pkg/matcher/macaddr/` — EDNS 65001 MAC 匹配核心
- `pkg/matcher/msg_matcher/query.go` — `ClientMacAddressMatcher` 对接点
- `git show d253ed8^:plugin/executable/forward/forward.go` — 被删除的旧 forward 插件
- `/data/SourceCode/dnsproxy/proxy/cache.go` — dnsproxy 缓存实现（golibs/cache 的用法参考）
- `/data/SourceCode/dnsproxy/upstream/upstream.go` — `AddressToUpstream` + `ExchangeParallel`
- `github.com/AdguardTeam/golibs/cache` — 字节限制 LRU 缓存
- `github.com/AdguardTeam/urlfilter` — DNS 规则过滤引擎
- `github.com/dnstap/golang-dnstap` — dnstap 输出库
