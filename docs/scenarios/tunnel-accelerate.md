# 情境：国内隧道加速（accel）

> 适用客户端：`/dns-query/accel`（client_id `accel`，别名 `tunnel-cn`）。
> 统一模型与分族语义见 [README](./README.md)。

## 场景

服务部署在国内机器的内网穿透上，同时保有 Cloudflare 副本供海外/有梯子用户，
同名 split-horizon：

- accel 客户端 → 解析到隧道入口 IP（加速）
- outdoor 客户端 → 解析到 Cloudflare（ECH 完整）

与内网加速不同，隧道入口没有权威 DNS 服务器，**端点健康（TCP 拨测）就是 gate**：
隧道挂掉时自动整域回落公网，恢复后自动切回。

## 配置

加速地址以 hosts 文件外部维护（可远程同步，如走 ofelia/update.sh）：

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
gitlab.example.com 1.2.3.4
app.example.com 5.6.7.8 2408:aaaa::1
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

## sequence 挂载

在 outdoor 判定之前、adg_cache 之前（cache 无 per-domain TTL，放后面会被缓存
遮蔽健康翻转）：

```yaml
exec:
  - if: match_client_accel          # client_matcher, client_id: [accel, tunnel-cn]
    exec:
      - tunnel_accelerate           # 命中并接管 → 结束；全死 → 穿透
  - if: match_client_outdoor
    exec: [split_forward]
  # ... 无 tag 现有链路
```

accel 客户端查询未登记域名 → 不命中 hosts → 穿透走后续公网分流，零额外配置。

## 客户端接入 **[待补充]**

- [ ] accel 客户端的具体形态（哪些设备/软路由、如何下发 `/dns-query/accel` 配置）
- [ ] 隧道服务清单与端口（哪些域名进 tunnel-hosts.txt、非 443 端口列表）

## 边界行为

| 情境 | 行为 |
|------|------|
| 单栈隧道（hosts 只配 v4） | AAAA 查询空 NOERROR，客户端只用 v4；公网 v6 不泄漏 |
| 部分端点死亡 | 只返回存活 IP；同族全死则该族抑制空应答 |
| 隧道端点全挂 | 整域回落 Cloudflare（含 ECH）；恢复后约 2 分钟自动切回 |
| hosts 未登记域名 | 穿透走公网分流 |
