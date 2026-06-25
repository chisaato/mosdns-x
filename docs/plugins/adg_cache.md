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
      prefetch: true           # 启用预刷新
      prefetch_ttl: 10         # 过期前 N 秒触发预刷新
      stale_ttl: 300           # 过期后最多还能用 N 秒
```

## 行为

| 场景 | 行为 |
|------|------|
| **未过期** | 直接返回缓存，调整 TTL |
| **已过期 + `optimistic=true` + 在 stale_ttl 内** | 返回 stale 缓存（TTL = optimistic_ttl），可选触发 prefetch |
| **已过期 + `optimistic=false` 或超出 stale_ttl** | 视为 miss，执行 next 链 |
| **未命中** | 执行 next 链，存储有效响应 |

## 缓存键

使用 `dnsutils.GetMsgKey(q, 0)` 生成，仅缓存简单查询（1 个 question，无 answer/ns/extra）。

## 预刷新

- 仅在 `optimistic=true` 且 stale 命中时触发
- 使用 `singleflight.Group` 去重，相同 key 的并发 prefetch 合并
- 后台 goroutine 执行，超时 5 秒
- 失败仅记日志，不阻塞当前请求

## 缓存值格式

```
[4B expiry unix timestamp big-endian][2B packed msg length big-endian][packed dns msg]
```

## 对比 mosdns 自带 cache

| 特性 | mosdns cache | adg_cache |
|------|:---:|:---------:|
| 容量限制 | 条数 | 字节数 |
| Evict | FIFO（默认） | LRU |
| 过期响应 | lazy update（过期后异步刷新） | optimistic（过期仍响应） |
| Prefetch | ❌ | ✅（过期前预刷新） |
| 后端 | mem_cache / redis | golibs/cache |
