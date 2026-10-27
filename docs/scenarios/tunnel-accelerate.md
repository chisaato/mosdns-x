# 情境：国内隧道加速（outdoor + tunnel-cn）

> 适用客户端：`/dns-query/outdoor/tunnel-cn`（两个 client_id 必须同时出现）。
> 统一模型与分族语义见 [README](./README.md)。

## 场景

服务部署在国内机器的内网穿透上，同时保有公网入口供不使用隧道的出门设备，
同名 split-horizon：

- outdoor + tunnel-cn 客户端 → 解析到隧道入口 IP（加速）
- 仅 outdoor 客户端 → 公网解析（ECH 等记录完整）；仅 tunnel-cn 不启用隧道

与内网加速不同，隧道入口没有权威 DNS 服务器，**端点健康（TCP 拨测）就是 gate**：
隧道挂掉时自动整域回落公网，恢复后自动切回。

## 配置

加速地址以 hosts 文件外部维护（可通过定时任务远程同步）：

```yaml
data_providers:
  tunnel_hosts:
    file: ./data/tunnel-hosts.txt

plugins:
  - tag: tunnel_accelerate
    type: tunnel_accelerate
    args:
      hosts:
        - "provider:tunnel_hosts"
      ttl: 30
      probe_port: 443
      # probe_port_map: {"app.example.com": 8443}   # 按域名覆盖端口
      probe_timeout: 1
      probe_cache_ttl: 60
```

`tunnel-hosts.txt`（hosts 格式，一行一个完整域名，可混合 v4/v6）：

```
service.example.com 192.0.2.10
app.example.com 198.51.100.10 2001:db8::1
```

完整参数说明见 [`docs/plugins/tunnel_accelerate.md`](../plugins/tunnel_accelerate.md)。

## 状态机

```
查询 domain ∈ hosts
  ├─ 本族 IP 拨测存活 → 返回存活 IP（TTL 30）
  ├─ 本族死/未配置，另一族活 → 空 NOERROR（本族抑制）
  ├─ 全部 IP 死亡 → 放行 → 落回公网链路（自动故障转移）
  └─ TYPE65 → 任一端点存活 → 空 NOERROR 掐 ECH；全死 → 放行
```

- 拨测粒度为**主机名级**：同 zone 下不同服务独立探测互不影响；
  同名多 IP 也是逐 IP 探测、只回存活 IP。
- 故障切换/恢复收敛 ≈ `probe_cache_ttl` + `ttl` + 客户端缓存 ≈ 2 分钟量级。
  回落公网的应答 TTL 同样被压到 `ttl`，避免公网 HTTPS（含 ECH）在隧道恢复后
  残留。adg_cache 不会把这类短 TTL 应答当 stale 继续返回（见下方说明）。

## sequence 挂载

在 outdoor 判定之前、adg_cache 之前（cache 无 per-domain TTL，放后面会被缓存
遮蔽健康翻转）：

```yaml
exec:
  # 先按 no-filter 决定是否执行广告过滤
  - if: "match_client_outdoor && match_client_tunnel_cn"
    exec:
      - tunnel_accelerate           # 命中并接管 → 结束；全死 → 穿透
      - split_forward               # 回落必须在同一分支内，供插件压短 TTL
      - _return
  - if: match_client_outdoor
    exec: [split_forward, _return]  # 终结分支
  # ... 无 outdoor 的内网权威链路
```

两个 matcher 分别匹配 `client_id: [outdoor]` 和 `[tunnel-cn]`；也可用
`client_id: [outdoor, tunnel-cn]` 配合 `match_all: true`，不可用默认 ANY。
查询未登记域名 → 不命中 hosts → 穿透走同分支的公网分流，零额外配置。

> **`_return` 的作用域**：mosdns 的 `if` 分支执行完会继续走外层后续节点；
> `_return` 写在 `split_forward` 这类子 sequence 内部也只退出子 sequence，外层
> 仍会继续。因此需要终结的分支（如 outdoor）要在**顶层分支里**写 `_return`，
> 否则 outdoor 应答会被后续 ech_block / forward_pdns 覆盖。
>
> 隧道回落只走公网，不能串入 pdns 内网加速；`split_forward` 放在插件后，
> 使插件能在回落应答后压短 TTL。过滤是否跳过只由 `no-filter` 决定。

> **与 adg_cache 乐观缓存的配合**：adg_cache 对缓存 TTL ≤ `stale_min_ttl`
> （默认 = `optimistic_ttl` = 30）的条目不做过期响应，加速应答与回落应答（TTL
> 均压到 `ttl`）过期即重新判定；其余条目 stale 命中时总是后台刷新。两个 30
> 需要保持 `ttl` ≤ `stale_min_ttl`，调大 `ttl` 时同步调大 `stale_min_ttl`。

## 客户端接入 **[待补充]**

- [ ] 出门客户端的具体形态（设备/软路由、如何下发 `/dns-query/outdoor/tunnel-cn`）
- [ ] 隧道服务清单与端口（哪些域名进 tunnel-hosts.txt、非 443 端口列表）

## 边界行为

| 情境 | 行为 |
|------|------|
| 单栈隧道（hosts 只配 v4） | AAAA 查询空 NOERROR，客户端只用 v4；公网 v6 不泄漏 |
| 部分端点死亡 | 只返回存活 IP；同族全死则该族抑制空应答 |
| 隧道端点全挂 | 整域回落 Cloudflare（含 ECH）；恢复后约 2 分钟自动切回 |
| hosts 未登记域名 | 穿透走公网分流 |
