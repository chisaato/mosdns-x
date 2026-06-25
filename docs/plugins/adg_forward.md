# adg_forward

基于 `github.com/AdguardTeam/dnsproxy/upstream` 的多协议 DNS 转发插件。

## 配置

```yaml
plugins:
  - tag: my_upstream
    type: adg_forward
    args:
      # ── 全局 bootstrap pool ──────────────────────────────
      # 所有 upstream 共享这些 bootstrap 服务器做域名解析。
      # 每个地址必须是纯 IP，支持任意协议（plain / DoH / DoT / DoQ）。
      bootstrap:
        - "https://1.12.12.12/dns-query"
        - "https://120.53.53.53/dns-query"

      # ── 上游地址列表 ──────────────────────────────────────
      upstream:
        - addr: "https://dns.adguard.com/dns-query"
        - addr: "tls://dns.alidns.com"
        - addr: "8.8.8.8:53"

      # 全局超时（秒），默认 5
      timeout: 10
```

## UpstreamConfig

```yaml
- addr: "https://dns.adguard.com/dns-query"   # 上游地址
  http3: false                                  # 启用 HTTP/3
  insecure_skip_verify: false                   # 跳过证书验证
  trusted: false                                # 标记为可信（第一个默认为 true）
```

## 支持的协议

| Scheme | 协议 | 默认端口 |
|--------|------|:-------:|
| 无 / `udp://` | 明文 UDP | 53 |
| `tcp://` | 明文 TCP | 53 |
| `tls://` | DNS-over-TLS | 853 |
| `https://` | DNS-over-HTTPS | 443 |
| `h3://` | DNS-over-HTTPS (HTTP/3) | 443 |
| `quic://` | DNS-over-QUIC | 853 |
| `sdns://` | DNS Stamp 解析 | 动态 |

## Bootstrap pool

- **所有 upstream 共享一个全局 bootstrap pool**，不是每个 upstream 单独配置
- pool 中的多个 bootstrap 服务器**并发查询**（ParallelResolver），返回第一个成功的
- 每个 bootstrap 地址必须是纯 IP（避免循环依赖）
- 支持任意纯 IP 协议：`1.12.12.12:53`、`https://1.12.12.12/dns-query`、`tls://1.12.12.12`
- 单个 bootstrap 时自动用 CachingResolver 包装，缓存 DNS 解析结果
- 不配置 bootstrap 时使用系统默认 DNS 解析器

## 执行逻辑

1. 接收 DNS 查询
2. 并发查询所有 upstream，返回第一个成功响应
3. 设置响应到 `qCtx.R()`
4. 调用 next 链（通常给 cache 插件）

## 说明

本插件使用 dnsproxy 的 `AddressToUpstream` 创建上游连接，dnsproxy 内部处理：
- 连接池复用（Keep-Alive）
- TLS 握手
- HTTP/2 / HTTP/3 协议协商
- 超时控制
