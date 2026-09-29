# adg_cache

基于 `github.com/AdguardTeam/golibs/cache` 的字节限制 LRU DNS 缓存。

## 配置

```yaml
plugins:
  - tag: my_cache
    type: adg_cache
    args:
      size: 52428800           # 字节限制，默认 50MB
      optimistic: true         # 过期后是否继续响应（默认 true）
      optimistic_ttl: 30       # 过期响应的 TTL（默认 30 秒）
      stale_min_ttl: 30        # 缓存时 TTL 不超过此值的条目不做过期响应（默认 = optimistic_ttl，负数关闭）
      prefetch: true           # 启用预刷新
      prefetch_ttl: 10         # 过期前 N 秒内命中即后台预刷新
      stale_ttl: 300           # 过期后最多还能用 N 秒
```

## 行为

| 场景 | 行为 |
|------|------|
| **未过期** | 直接返回缓存，调整 TTL；`prefetch=true` 且剩余 TTL ≤ prefetch_ttl 时后台预刷新 |
| **已过期 + `optimistic=true` + 在 stale_ttl 内 + 缓存 TTL > stale_min_ttl** | 返回 stale 缓存（TTL = optimistic_ttl），**并总是后台刷新** |
| **已过期 + 不满足上一行任一条件** | 视为 miss，执行 next 链 |
| **未命中** | 执行 next 链，存储有效响应 |

### 为什么短 TTL 条目不做过期响应

上游插件用短 TTL 表达"这个结论很快会变"：`tunnel_accelerate` 的拨测应答与回落
应答（`ttl`，默认 30）、`ech_block` 的放行应答（`max_pass_ttl`，默认 30）。
过期后再以 `optimistic_ttl` 返回，等于把这些结论延长到超出它们自身的有效期，
加速链路就会出现"公网 ECH + 加速 IP"的毛刺。`stale_min_ttl` 默认等于
`optimistic_ttl`，恰好把这类应答排除在外；普通公网记录（TTL 通常远大于 30）
照常享受乐观缓存。

注意：上游若本身也是缓存（如公共递归），返回的剩余 TTL 可能偶尔很小，这类条目
在当前周期内不做过期响应，下次刷新后恢复。

## 缓存键

```
报文（ID 置 0，去掉 OPT） + ECS（family + 掩码 + 按掩码截断的地址） + client_id
```

- 只缓存单 question、无 answer/ns 的查询；extra 只允许 OPT（带 TSIG 等不缓存）
- ECS 按 **source 掩码截断后**入键，不是确切 IP：`ecs` 插件默认 `/24`、`/48`，
  同一网段的客户端共用一个条目
- 键不看应答的 scope：按 source 网段分桶总是正确的，代价只是 scope/0 的非地域
  记录在每个网段各存一份。上游回显的 scope 并不可靠（Quad9 不回显、私网 ECS
  被当成无效却仍回显 scope/24），不据此合并条目
- 放在缓存**之后**、且会影响应答的判定，必须体现在键里：client_id 在键里；
  按 MAC 或确切客户端 IP 的分支不在键里，需要放在缓存之前处理

ECS 的完整流向见 [`ecs`](ecs.md)。

## 后台刷新

两个触发点，共用同一套刷新逻辑：

- **stale 命中**：总是触发。stale 应答只返回到刷新完成为止，而不是整个
  `stale_ttl`；上游慢（如海外转发）时客户端仍即时拿到旧应答。
- **预刷新**（`prefetch=true`）：未过期、剩余 TTL ≤ `prefetch_ttl` 时触发，热门
  条目在过期前就被续上，不会进入 stale。整个 TTL 都落在窗口内的条目
  （TTL ≤ `prefetch_ttl`）不预刷新，否则每次命中都会刷新。

实现：

- 使用 `singleflight.Group` 去重，相同 key 的并发刷新合并
- 后台 goroutine 执行，超时 5 秒
- 失败或上游返回非 NOERROR 时不覆盖缓存，旧条目继续按 stale 规则服务
- 不阻塞当前请求

## 指标

注册在 `api.http` 的 `/metrics`，前缀 `mosdns_plugin_<tag>_`（与 mosdns 自带
cache 一致；`observability` 插件的独立端口不包含这些指标）：

| 指标 | 类型 | 说明 |
|------|------|------|
| `query_total` | Counter | 进入缓存查找的查询 |
| `hit_total` | Counter | 未过期命中 |
| `stale_hit_total` | Counter | 过期响应命中 |
| `refresh_total` | Counter | 实际执行的后台刷新（预刷新 + stale） |
| `refresh_failed_total` | Counter | 后台刷新返回错误 |
| `evicted_total` | Counter | LRU 为腾空间逐出的条目 |
| `evicted_live_total` | Counter | 其中逐出时仍可服务（未超过 expiry + `stale_ttl`）的条目 |
| `entries` | Gauge | 当前条目数 |
| `size_bytes` | Gauge | 当前键 + 值占用字节，受 `size` 约束 |
| `max_size_bytes` | Gauge | 配置的 `size` |

常用算式：

```promql
# 命中率（含 stale）
(rate(mosdns_plugin_cache_hit_total[1h]) + rate(mosdns_plugin_cache_stale_hit_total[1h]))
  / rate(mosdns_plugin_cache_query_total[1h])

# 容量是否够：持续 > 0 说明有还能用的条目被挤掉，应调大 size
rate(mosdns_plugin_cache_evicted_live_total[1h])

# 平均条目大小
mosdns_plugin_cache_size_bytes / mosdns_plugin_cache_entries
```

（示例中插件 tag 为 `cache`。）

### 容量与 ECS 分桶

`size` 是字节上限，LRU 逐出，**不会无界增长**；ECS 分桶的代价体现在命中率而不
是内存。条目约 200–500 字节（键约 50 字节，值为带 ECS OPT 的应答），实际均值
看 `size_bytes / entries`：

| size | 约可容纳 |
|------|---------|
| 5 MB | 1–2.5 万条 |
| 50 MB（默认） | 10–25 万条 |

需要的条目数 ≈ 活跃网段数 × 每个网段的活跃域名数。移动网络换基站、CGNAT 换出口
都会带来新网段（v6 `/48` 尤其容易变），新网段从冷缓存开始，旧网段的条目留到被
LRU 挤掉。`evicted_live_total` 增长说明容量不够；只有 `evicted_total` 增长、
`evicted_live_total` 不动，说明被逐出的都是早已过期的旧网段条目，容量足够。

## 缓存值格式

```
[4B expiry unix timestamp big-endian][2B packed msg length big-endian][packed dns msg]
```

## 对比 mosdns 自带 cache

| 特性 | mosdns cache | adg_cache |
|------|:---:|:---------:|
| 容量限制 | 条数 | 字节数 |
| Evict | FIFO（默认） | LRU |
| 过期响应 | lazy update（过期后异步刷新） | optimistic（过期仍响应 + 异步刷新） |
| Prefetch | ❌ | ✅（过期前预刷新） |
| 后端 | mem_cache / redis | golibs/cache |
