# mosdns-x AdGuard 集成实现计划

## 概述

在 mosdns-x 中新增 3 个可执行插件，将 AdGuard Home 的核心过滤/缓存/转发能力嫁接到 mosdns 流水线中。

**新增插件**: `forward`, `adg_filter`, `adg_cache`
**新增依赖**: `github.com/AdguardTeam/dnsproxy`, `github.com/AdguardTeam/golibs`, `github.com/AdguardTeam/urlfilter`

---

## 1. forward 插件

### 设计

封装 `github.com/AdguardTeam/dnsproxy/upstream` 到 mosdns 插件系统中。

### 配置结构

```yaml
plugins:
  - tag: my_forward
    type: forward
    args:
      upstream:
        - addr: "https://dns.adguard.com/dns-query"   # 必需: 上游地址
          bootstrap: "https://1.12.12.12/dns-query"    # 可选: IP-based bootstrap
          enable_http3: false                          # 可选: 启用 HTTP/3
          insecure_skip_verify: false                  # 可选: 跳过证书验证
        - addr: "tls://dns.alidns.com"
          bootstrap: "120.53.53.53:53"                 # 支持所有纯IP协议
      timeout: 10                                       # 秒, 默认5
```

### 核心逻辑

1. `AddressToUpstream(addr, opts)` 为每个上游创建 dnsproxy upstream
2. 如果配置了 `bootstrap`, 创建 `NewUpstreamResolver(bootstrapAddr)` + `NewCachingResolver()`
   - 单 bootstrap 地址 + DNS 缓存, 足以满足生产需求
3. 包装为 `bundled_upstream.Upstream` 接口 (Exchange + Address + Trusted)
4. Exec 中调用 `bundled_upstream.ExchangeParallel()` 并发查询
5. 响应设置: `qCtx.SetResponse(r)`

### 关键接口适配

dnsproxy `Upstream.Exchange(req *dns.Msg)` 无 ctx → 通过 `Options.Timeout` 控制超时
dnsproxy `Upstream` → 适配为 mosdns `bundled_upstream.Upstream`

### 文件

- `plugin/executable/forward/forward.go` (~150 行)

---

## 2. adg_filter 插件

### 设计

基于 `github.com/AdguardTeam/urlfilter` 的 DNS 过滤引擎。

### 配置结构

```yaml
plugins:
  - tag: adg_block
    type: adg_filter
    args:
      # 内联规则 (AdBlock 语法或纯域名)
      rules:
        - "||example.com^"
        - "ads.example.net"
      
      # 本地规则文件 (可选)
      rules_file:
        - "/etc/mosdns/custom-rules.txt"
      
      # 远程过滤列表 URL (自动下载 + 定时更新)
      urls:
        - url: "https://example.org/filter.txt"
          name: "My Custom Filter"
        - url: "https://cdn.example.com/adblock.txt"
          name: "AdBlock List"
      
      # 白名单规则 (内联, 可选)
      whitelist_rules:
        - "@@||allowed-ads.example.com^"
        - "tracking.example.net"
      
      # 白名单远程 URL (可选)
      whitelist_urls:
        - url: "https://example.org/allowlist.txt"
          name: "My Allowlist"
      
      # 阻断模式
      block_mode: "nxdomain"    # nxdomain | refused | zero_ip | custom_ip
      blocking_ipv4: "0.0.0.0"  # zero_ip/custom_ip 模式使用
      blocking_ipv6: "::"        # zero_ip/custom_ip 模式使用
      
      # 自动更新间隔 (秒), 默认 86400 (24h)
      update_interval: 86400
```

### 核心架构

```
引擎(双引擎架构):
  ┌─────────────────┐
  │  Whitelist Engine │ ← whitelist_rules + whitelist_urls
  │  (urlfilter.DNSEngine)
  └────────┬────────────┘
           │ 先匹配
  ┌────────▼────────────┐
  │  Blocklist Engine   │ ← rules + rules_file + urls
  │  (urlfilter.DNSEngine)
  └──────────────────────┘

URL自动更新:
  Ticker(update_interval) → HTTP GET → 验证 → 重建 DNSEngine → sync.RWMutex swap
```

### 匹配流程 (Exec)

1. 从 `qCtx.Q()` 提取域名和查询类型
2. 创建 `urlfilter.DNSRequest{Hostname, DNSType}`
3. 先查 whitelist engine → 命中 → 放行 (调 next)
4. 再查 blocklist engine → 命中 → 生成阻断响应
   - `nxdomain`: `dnsutils.GenEmptyReply(q, dns.RcodeNameError)`
   - `refused`: `dnsutils.GenEmptyReply(q, dns.RcodeRefused)`
   - `zero_ip` / `custom_ip`: 构建 A/AAAA 记录响应 (参考 blackhole 插件)
5. 未命中 → 调 next

### 规则加载

```go
// 从文本创建 rulelist
filterlist.NewString(&filterlist.StringConfig{
    ID:             id,
    RulesText:      strings.Join(rules, "\n"),
    IgnoreCosmetic: true,  // DNS 过滤不需要 cosmetic 规则
})

// 从文件创建 rulelist
filterlist.NewFile(&filterlist.FileConfig{
    ID:             id,
    Path:           filePath,
    IgnoreCosmetic: true,
})

// 组合到 RuleStorage → 创建 DNSEngine
storage, _ := filterlist.NewRuleStorage([]filterlist.Interface{list1, list2, ...})
engine := urlfilter.NewDNSEngine(storage)
```

### URL 自动更新

- 启动时同步下载所有 URL
- 后台 ticker 定时更新
- 下载失败保留旧引擎 (不中断服务)
- 一次请求失败不影响其他 URL
- 使用 `hash/crc32` 校验变化, 无变化跳过重建

### 文件

- `plugin/executable/adg_filter/adg_filter.go` (~350 行)

---

## 3. adg_cache 插件

### 设计

基于 `github.com/AdguardTeam/golibs/cache` 的字节限制 LRU 缓存。

### 配置结构

```yaml
plugins:
  - tag: adg_cache
    type: adg_cache
    args:
      size: 52428800           # 字节限制 (默认 64KB, 推荐 50MB)
      prefetch: true           # 启用预刷新
      prefetch_ttl: 10         # 过期前 N 秒异步刷新
      stale_ttl: 300           # 过期后还能用 N 秒
      optimistic_ttl: 30       # 乐观缓存默认 TTL
```

### 与现有 cache 插件对比

| 特性 | cache | adg_cache |
|------|:-----:|:---------:|
| 容量限制 | 条数 | 字节数 |
| Evict | FIFO(默认) | LRU |
| Prefetch | ❌ (仅lazy update) | ✅ (过期前刷新) |
| Stale | 固定 lazy_cache_ttl | 可控 stale_ttl |
| 后端 | mem_cache/redis | golibs/cache |
| Singleflight | ✅ | ✅ |

### 核心逻辑

1. 后端: `glcache.New(glcache.Config{MaxSize: ..., EnableLRU: true})`
2. Key: DNS question 序列化 (Qname + Qtype + Qclass + DO bit)
3. Value: `[4B timestamp][2B msg_len][packed_msg]`
4. Exec: 查缓存 → 命中: setResponse + prefetch; 未命中: exec next + store
5. Prefetch: 在过期前 `prefetch_ttl` 秒, 启动后台 goroutine 执行 next 并更新
6. Singleflight 去重: 相同 key 的 prefetch 合并

### 文件

- `plugin/executable/adg_cache/adg_cache.go` (~200 行)

---

## 4. 依赖安装

```bash
go get github.com/AdguardTeam/dnsproxy@latest
go get github.com/AdguardTeam/golibs@latest
go get github.com/AdguardTeam/urlfilter@latest
go mod tidy
```

注意: `dnsproxy` 需要 Go 1.26 的 quic-go 等依赖, 需检查与现有 go.mod 的兼容性。

## 5. 注册

在 `plugin/enabled_plugin.go` 添加:
```go
_ "github.com/pmkol/mosdns-x/plugin/executable/forward"
_ "github.com/pmkol/mosdns-x/plugin/executable/adg_filter"
_ "github.com/pmkol/mosdns-x/plugin/executable/adg_cache"
```

## 6. 验证

- `go build -o mosdns main.go` 编译通过
- `go test ./plugin/` 插件 init() 注册正常
- `go vet ./plugin/executable/forward/ ./plugin/executable/adg_filter/ ./plugin/executable/adg_cache/` 无问题

## 7. 风险与注意事项

- dnsproxy 内部 `internal/bootstrap` 包不可导入, bootstrap 只支持单地址 + CachingResolver
- urlfilter 规则更新时需要重建 DNSEngine, 大规则集会短暂阻塞, 用 RWMutex + 异步构建缓解
- golibs/cache 的 OnDelete 回调在 LRU evict 时触发, 需确保不阻塞
- quic-go 版本可能与现有依赖冲突, 需 `go mod tidy` 后检查
