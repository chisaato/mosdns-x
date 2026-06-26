# adg_filter

基于 `github.com/AdguardTeam/urlfilter` 的 DNS 过滤插件，对标 AdGuard Home 的过滤引擎。

## 配置

```yaml
plugins:
  - tag: my_filter
    type: adg_filter
    args:
      # ── 拦截列表 ──────────────────────────────────────────────
      block_lists:
        - url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
          name: "AdGuard DNS filter"
        - url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt"
          name: "HaGeZi Pro++"

      # 手工填写的拦截规则 (AdBlock 语法或纯域名)
      block_inline:
        - "||evil.example.com^"
        - "ads.example.net"
        - "0.0.0.0 tracker.example.com"

      # ── 白名单 ──────────────────────────────────────────────
      allow_lists:
        - url: "https://example.com/my-allowlist.txt"
          name: "My allowlist"

      allow_inline:
        - "@@||good-ads.example.com^"

      # ── 阻断模式 ──────────────────────────────────────────────
      block_mode: nxdomain      # nxdomain | refused | zero_ip | custom_ip
      blocking_ipv4: "0.0.0.0" # zero_ip / custom_ip 时使用
      blocking_ipv6: "::"

      # 本地缓存目录（可选），启用后过滤列表会缓存到该目录。
      # 重启时优先读取本地缓存，避免重新下载；下载失败时也回退到缓存。
      cache_dir: "/var/lib/mosdns/adg_cache"

      # 自动更新间隔（秒），默认 86400（24h）
      update_interval: 86400
```

## 阻断模式

| 模式 | 效果 |
|------|------|
| `nxdomain` | 返回 NXDOMAIN（默认） |
| `refused` | 返回 REFUSED |
| `zero_ip` | A → `0.0.0.0`，AAAA → `::` |
| `custom_ip` | A → blocking_ipv4，AAAA → blocking_ipv6 |

非 A/AAAA 查询在 IP 阻断模式下回退到 NXDOMAIN。

## 规则来源

- `block_lists` / `allow_lists`：从 URL 下载，定时自动更新
- `block_inline` / `allow_inline`：内联规则，重启生效

支持 AdBlock 语法（`||domain.com^`）、纯域名列表、hosts 格式。

## 本地缓存

配置 `cache_dir` 后可启用本地磁盘缓存：

- **加速启动**：重启时优先读取本地缓存文件，避免每次启动都重新下载
- **断网保护**：定时更新或启动时下载失败时，自动回退到本地缓存
- **缓存文件名**：每个 URL 的 SHA256 哈希值，无过期问题（由 `update_interval` 控制更新频率）
- **缓存更新**：每次成功下载后自动刷新本地缓存文件

## 匹配流程

```
收到 DNS 请求
  ├─ allow engine 匹配 → 放行（调 next）
  ├─ block engine 匹配 → 阻断（拦截响应，不调 next）
  └─ 均不匹配 → 放行（调 next）
```

## URL 自动更新

启动时同步下载所有 URL 列表，合并到 `urlfilter.DNSEngine`。
后台按 `update_interval` 定时刷新，下载失败保留旧引擎不中断服务。
