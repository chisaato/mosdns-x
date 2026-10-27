# 情境：公网直连（outdoor）

> 适用客户端：`/dns-query/outdoor`（client_id `outdoor`）——不在家（出门）的设备。

## 场景

未同时携带 `tunnel-cn` 时，跳过全部加速分支，直接公网分流：

```
match_client_outdoor → split_forward
  ├─ cn 域 → 国内 DoH
  └─ 其余 → 海外加密 DoH（Cloudflare 权威）
```

- Cloudflare 侧记录含 ECH 配置，客户端完整可用（这正是加速情境要对内网/隧道
  客户端阻断 TYPE65 的原因——他们拿 Cloudflare 的 ECH 公钥连内网/隧道 IP 必失败）。
- `outdoor` 不代表跳过广告过滤；只有同时携带 `no-filter` 才跳过过滤。

## sequence 位置

```yaml
exec:
  # 广告过滤先按 no-filter 判定；隧道分支在前（outdoor + tunnel-cn）
  - if: match_client_outdoor
    exec: [split_forward, _return]  # _return 必须在顶层分支内，否则会串入无 tag 链路
  # ... 无 outdoor 的内网权威链路
```

## 适用判断

| 客户端状态 | 推荐入口 |
|-----------|----------|
| 出门，使用公网 | `/dns-query/outdoor` |
| 出门，希望国内隧道加速 | `/dns-query/outdoor/tunnel-cn` |
| 在家 | `/dns-query`（单独 tunnel-cn 也按在家处理） |
