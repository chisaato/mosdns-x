# 情境：公网直连（outdoor）

> 适用客户端：`/dns-query/outdoor`（client_id `outdoor`）——海外设备或挂梯子的国内设备。

## 场景

跳过全部加速分支，直接公网分流：

```
match_client_outdoor → split_forward
  ├─ cn 域 → 国内 DoH
  └─ 其余 → 海外加密 DoH（Cloudflare 权威）
```

- Cloudflare 侧记录含 ECH 配置，客户端完整可用（这正是加速情境要对无 tag/accel
  客户端阻断 TYPE65 的原因——他们拿 Cloudflare 的 ECH 公钥连内网/隧道 IP 必失败）。
- outdoor 客户端**不经过** adguard 过滤与 cache 之外的加速链路（见 sequence 布局）。

## sequence 位置

```yaml
exec:
  # tunnel_accelerate 分支在前（仅 accel 客户端命中）
  - if: match_client_outdoor
    exec: [split_forward, _return]  # _return 必须在顶层分支内，否则会串入无 tag 链路
  # ... 无 tag 链路
```

## 适用判断

| 客户端网络 | 推荐入口 |
|-----------|----------|
| 海外 | `/dns-query/outdoor` |
| 国内 + 梯子全局 | `/dns-query/outdoor`（走梯子访问 CF 通常优于直连内网/隧道） |
| 国内无梯子 | `/dns-query` 或 `/dns-query/accel` |
