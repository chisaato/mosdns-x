# adg_forward

基于 `github.com/AdguardTeam/dnsproxy/upstream` 的多协议 DNS 转发插件，支持三种上游模式。

## 配置

```yaml
plugins:
  - tag: my_upstream
    type: adg_forward
    args:
      # ── 上游模式 ────────────────────────────────────────────
      # load_balance  | parallel  | fastest_addr
      # 默认 load_balance（基于 RTT 加权随机）
      mode: load_balance

      # ── 全局 bootstrap pool ──────────────────────────────
      # 所有 upstream 共享这些 bootstrap 服务器做域名解析。
      # 每个地址必须是纯 IP（避免循环依赖），支持任意协议。
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

      # ── client_id 出站透传（多节点转发）─────────────────────
      # 把请求元数据中的 clientIDs 以 path 段形式追加到每个 upstream
      # addr 的路径后（/dns-query + "/" + id1 + "/" + id2 ...），
      # 用于边缘节点向中枢转发时保留客户端身份，供中枢按 tag 路由。
      # 默认 false（行为与不配置时完全一致）
      # client_id_passthrough: true
      # 每个"不同 client_id 集合"懒构建一组变体 upstream，LRU 缓存容量
      # passthrough_cache_size: 16
```

## UpstreamConfig

```yaml
- addr: "https://dns.adguard.com/dns-query"   # 上游地址
  http3: false                                  # 启用 HTTP/3
  insecure_skip_verify: false                   # 跳过证书验证
  trusted: false                                # 标记为可信（第一个默认为 true）
```

## 上游模式

| 模式 | 枚举值 | 行为 |
|------|--------|------|
| **加权负载均衡** | `load_balance` (默认) | 记录每个上游的历史 RTT，按 RTT 倒数加权随机选择。延迟越低命中概率越高 |
| **并行请求** | `parallel` | 同时发送给所有上游，返回第一个成功响应 |
| **最快 IP** | `fastest_addr` | 查询所有上游，收集返回的所有 IP → ICMP/TCP ping 测速 → 只保留最快 IP 的响应。仅对 A/AAAA 生效，其他类型回退到负载均衡 |

### 最快 IP（fastest_addr）说明

该模式对应 AdGuard 的 "parallel" + "fastest IP" 组合：
1. 并发查询所有上游
2. 聚合所有响应中的 IP 地址
3. 对每个 IP 做 TCP ping（端口 80、443）
4. 返回响应最快 IP 的策略，过滤掉其他 IP
5. 内置 IP 缓存，避免重复 ping

## Bootstrap pool

- **所有 upstream 共享一个全局 bootstrap pool**
- pool 中的多个 bootstrap 服务器**并发查询**（ParallelResolver），返回第一个成功的
- 每个 bootstrap 地址**必须是纯 IP**（避免循环依赖）
- 支持任意纯 IP 协议：`1.12.12.12:53`、`https://1.12.12.12/dns-query`、`tls://1.12.12.12`
- 单 bootstrap 时自动用 CachingResolver 包装，缓存 DNS 解析结果
- 不配置 bootstrap 时使用系统默认 DNS 解析器

## client_id 透传（多节点转发）

`client_id_passthrough: true` 时，出站请求会把客户端带来的 client_id 集合
动态拼接到 upstream URL 的 path 后（见 [`doh-path.md`](../doh-path.md)）：

```
客户端 → 边缘: /dns-query/accel/international     (clientIDs = [accel, international])
边缘   → 中枢: https://hub:4215/dns-query/accel/international
```

- **顺序无关**：缓存 key 按 client_id 排序后生成，`/a/b` 与 `/b/a` 复用同一组 upstream
- **变体 upstream 懒构建**：每个不同的 client_id 集合构建一组变体（保持
  load_balance/parallel/fastest_addr 各模式结构），LRU 缓存，超过
  `passthrough_cache_size` 逐出并关闭被逐出的连接池；实际组合通常为个位数
- **无 client_id 的查询**直接使用原始 upstream，不产生变体
- 典型部署见 [`scenarios/hub-edge.md`](../scenarios/hub-edge.md)

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

## 说明

本插件使用 dnsproxy 的 `AddressToUpstream` 创建上游连接，dnsproxy 内部处理：
- 连接池复用（Keep-Alive）
- TLS 握手
- HTTP/2 / HTTP/3 协议协商
- 超时控制
