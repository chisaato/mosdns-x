# 情境：内网加速（无 tag）

> 适用客户端：`/dns-query`（无 client_id tag）的内网/国内设备。
> 统一模型与分族语义见 [README](./README.md)。

## 场景

访问 K3S 上部署的服务（自有 zone，如 `internal.example.com`）。
K3S external-dns 将服务记录写入 pdns（RFC2136 DNS Update），**pdns 记录存在性 =
"服务已在内网部署"的真理来源**：

- 服务部署 → 记录出现 → 无 tag 客户端解析到内网 IP
- 服务删除 → external-dns 清理记录 → 自动回落公网（Cloudflare）

## 流程

```
查询 domain ∈ internal_accelerate
  ├─ TYPE65 → ech_block：并发探测 pdns A+AAAA，任一存在 → 空 NOERROR
  ├─ A/AAAA → forward_pdns
  │    ├─ NOERROR（含空答案）→ _return     ← 有答案=内网 IP；空答案=单栈缺族抑制
  │    └─ NXDOMAIN / 出错 → 落回 split_forward（公网，服务未部署在 K3S）
  └─ 其他 qtype → split_forward
```

## 要点

- `_response_noerror`（response_matcher preset）替代旧 `_response_valid_answer`：
  **NOERROR 空答案不再穿透公网**。pdns 权威对"zone 内存在但无该族记录"返回
  NOERROR 空、对"名字不存在"返回 NXDOMAIN，恰好对应「在 gate 缺族 → 抑制」与
  「不在 gate → 放行」两种语义。
- K3S 场景没有"拨测"概念——记录存在即活。单栈集群只推一族时，另一族永远空应答
  （客户端只用存活族），这是防「内网 v4 + 公网 v6」混族泄漏的关键。
- ech_block 放行时（未命中 pdns / 探测失败）把公网 TYPE65 应答 TTL 压到
  `max_pass_ttl`（默认 = `cache_ttl`）：服务刚部署进 K3S 时，客户端缓存里的
  Cloudflare ECH 配置最多残留一个 `cache_ttl`，不会拿着它去连新出现的内网 IP。
- ech_block 使用**双族探测**（A+AAAA 任一存在即阻断）：v6-only 集群只登记 AAAA
  时旧版只探 A 会漏判，导致客户端拿到 Cloudflare 的 ECH 公钥去连内网 IP 而握手失败。
- pdns 库中存在仅有 `a-`/`aaaa-` TXT 而无地址记录的孤儿条目（如 minio 相关记录），
  gate 判定以实际 A/AAAA 存在性为准，孤儿 TXT 不构成 gate。

## 配置要点（sequence 片段）

```yaml
exec:
  # ... hosts → ecs → adg_filter → adg_cache
  - if: match_internal_accelerate
    exec:
      - block_internal_accelerate_domain_ecs   # ech_block, block_mode: empty
      - forward_pdns                            # 127.0.0.1:2653
      - if: _response_noerror                   # NOERROR（含空答案）
        exec: [_return]
      # NXDOMAIN → 穿透到下面的 split_forward
  - split_forward                               # cn DoH / 海外加密 DoH
```

## 边界行为

| 情境 | 行为 |
|------|------|
| 单栈 K8S 只推 A | AAAA 查询返回空 NOERROR，客户端只用内网 v4；公网 v6 不泄漏 |
| 单栈 K8S 只推 AAAA | 对称：A 查询空应答，只用内网 v6 |
| 服务已删（NXDOMAIN） | 回落公网，走 Cloudflare |
| pdns 超时/出错 | 回落公网（降级可用） |
| v6-only 集群 | ech_block 双族探测照常阻断 ECH |

## 相关插件

- [`ech_block`](../plugins/ech_block.md)
- [`response_matcher` 的 `_response_noerror`](../../plugin/matcher/response_matcher/response_matcher.go)
