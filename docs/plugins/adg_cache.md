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

使用 `dnsutils.GetMsgKey(q, 0)` 生成，仅缓存简单查询（1 个 question，无 answer/ns/extra）。

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
