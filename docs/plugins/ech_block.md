# ech_block

阻断 HTTPS (TYPE65) 资源记录查询，用于局域网 DNS 劫持场景。

## 背景

当域名被劫持时，内网 DNS 通常会返回该域名的 A/AAAA 记录（指向内网 IP），但中继
上游（如 Cloudflare）会返回包含 ECH Config 的 HTTPS 记录。

内网环境没有 ECH，如果将上游的 HTTPS 记录原样返回，客户端会尝试使用 ECH 连接失败，
导致降级或连接错误。`ech_block` 的核心思路是：

```
TYPE65 查询 example.com
  → 向 probe_dns 查询 example.com A 记录
    ├─ A 记录非空（说明被内网 DNS 劫持了）→ 阻断 TYPE65
    └─ 无 A 记录（说明未被劫持）→ 放行到上游
```

阻断后客户端回退到 A/AAAA 查询，正常连接劫持后的内网 IP。

## 配置

```yaml
plugins:
  - tag: block_ech
    type: ech_block
    args:
      # 必填 - 内网 DNS 地址，用于 A 记录探测
      probe_dns: "10.96.0.10:53"

      # 可选 - 探测超时（毫秒），默认 500
      probe_timeout: 500

      # 可选 - 阻断方式，默认 refused
      #   refused  返回 REFUSED
      #   nxdomain 返回 NXDOMAIN
      #   empty    返回 NOERROR + 空 Answer
      block_mode: "refused"

      # 可选 - 探测结果 LRU 缓存
      cache_size: 10000          # 容量，默认 10000
      cache_ttl: 60              # TTL 秒，默认 30

      # 可选 - 白名单域名，支持 provider: 引用
      allow_domains:
        - "valid-ech.internal.example.com"
```

## 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|:----:|:----:|------|
| `probe_dns` | `string` | 是 | - | 内网 DNS 地址，如 `192.168.1.1:53`，省略端口时默认 53 |
| `probe_timeout` | `int` | 否 | 500 | 探测超时（毫秒） |
| `block_mode` | `string` | 否 | `refused` | 阻断方式：`refused` / `nxdomain` / `empty` |
| `cache_size` | `int` | 否 | 10000 | 探测结果 LRU 缓存容量 |
| `cache_ttl` | `int` | 否 | 30 | 缓存秒数 |
| `allow_domains` | `[]string` | 否 | 无 | 白名单域名，支持 `provider:` 引用 |

## 执行逻辑

```
TYPE65 查询进入 ech_block
  │
  ├─ QType != 65 → 透传（不处理非 HTTPS 查询）
  │
  ├─ 命中 allow_domains → 透传（白名单放行）
  │
  ├─ 缓存命中且未过期 → 直接使用缓存结果
  │
  └─ 缓存 miss → 向 probe_dns 发起 A 记录探测
      │
      ├─ 探测失败 → 放行（失败安全，宁可漏不可误杀）
      │
      ├─ A 记录非空 → 阻断（返回 REFUSED / NXDOMAIN / 空应答）
      │  并缓存结果
      │
      └─ 无 A 记录 → 透传（未被劫持）
         并缓存结果
```

## 典型用法

### 基础：阻断劫持域名，其余正常

将 `ech_block` 放在所有上游查询之前。阻断后不继续执行链。

```yaml
plugins:
  - tag: block_ech
    type: ech_block
    args:
      probe_dns: "10.96.0.10:53"
      block_mode: "refused"
      cache_size: 10000
      cache_ttl: 60

  - tag: main_sequence
    type: sequence
    args:
      exec:
        - exec: $block_ech          # 先过阻断
        - exec: $upstream_cf        # 再查上游
```

### 只阻断指定域名

配合 `sequence` 的 `if` 判断，精确控制哪些域名走阻断逻辑。

```yaml
plugins:
  - tag: block_ech
    type: ech_block
    args:
      probe_dns: "10.96.0.10:53"

  - tag: hijacked_domains
    type: query_matcher
    args:
      domain:
        - "provider:my_hijacked_list"

  - tag: main_sequence
    type: sequence
    args:
      exec:
        - if: "$hijacked_domains"
          exec:
            - block_ech
            - _return
        - exec: $upstream_cf
```

### 带白名单的精确控制

对某些域名（如自家 CDN 正确部署了 ECH 的）即使被劫持也放行 TYPE65。

```yaml
plugins:
  - tag: block_ech
    type: ech_block
    args:
      probe_dns: "10.96.0.10:53"
      allow_domains:
        - "my-cdn.internal.example.com"
        - "provider:ech_allow_list"

  - tag: main_sequence
    type: sequence
    args:
      exec:
        - exec: $block_ech
        - exec: $upstream_cf
```

### 多层序列：先阻断，再选上游

结合 `dual_selector` 或 `adg_forward` 做完整的本地 DNS 策略。

```yaml
plugins:
  - tag: block_ech
    type: ech_block
    args:
      probe_dns: "10.96.0.10:53"
      block_mode: "nxdomain"

  - tag: cf_over_https
    type: adg_forward
    args:
      upstream:
        - addr: "https://dns.cloudflare.com/dns-query"

  - tag: fallback_udp
    type: fast_forward
    args:
      upstream:
        - addr: "8.8.8.8:53"

  - tag: main_sequence
    type: sequence
    args:
      exec:
        - exec: $block_ech
        - exec: $cf_over_https

  - tag: server_entry
    type: sequence
    args:
      exec:
        - exec: $main_sequence
        - exec: $fallback_udp
```

## 数据来源

```yaml
data_providers:
  my_hijacked_list:
    file: ./data/hijacked_domains.txt
```

`hijacked_domains.txt` 每行一个域名，空行和 `#` 开头的行为注释：

```
# 被劫持的域名列表
example.com
www.example.com
*.internal.example.com
```

## 与 query_matcher 的关系

`ech_block` 内置了域名匹配能力（通过 `query_matcher` 一样的 `domain` 库），但关注点不同：

| 维度 | query_matcher | ech_block |
|------|---------------|-----------|
| 匹配时机 | 仅匹配查询本身 | 匹配查询 + 动态 DNS 探测 |
| 阻断能力 | 无（需配合 if 再指向其他插件） | 内置阻断 |
| 动态决策 | 不能 | 能实时查内网 DNS 判断是否被劫持 |

## 注意事项

- `probe_dns` 必须是可直达的纯 IP 地址，避免循环依赖
- 探测使用 `dnsproxy_upstream.AddressToUpstream`（与 `adg_forward` 一致），
  支持 UDP/TCP/TLS/DOH 等多种协议，但内网场景通常用 UDP 就够了
- 缓存存的是域名粒度的"是否被劫持"标记，不含具体 IP
- 默认 30s TTL 适合劫持列表变化不频繁的场景；变化频繁可调小 `cache_ttl`
