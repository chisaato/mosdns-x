# tunnel_accelerate

国内隧道加速：对 hosts 文件登记的域名做 TCP 拨测，隧道存活时返回隧道 IP
（hosts 式应答），死亡时自动回落公网；TYPE65 (HTTPS) 查询在隧道存活时返回
空 NOERROR 以阻断 ECH 公钥分发。

## 背景

服务同时部署在国内内网穿透（加速入口）与 Cloudflare（海外副本）两侧，同名
split-horizon。国内客户端应解析到隧道 IP，海外/有梯子客户端解析到 Cloudflare。

与 pdns 内网加速（记录存在性 gate）不同，隧道入口没有权威 DNS 服务器，
**端点健康（TCP 拨测）就是 gate**：隧道挂掉时自动整域回落公网，恢复后自动切回。

## 配置

```yaml
data_providers:
  tunnel_hosts:
    file: ./data/tunnel-hosts.txt

plugins:
  - tag: tunnel_accelerate
    type: tunnel_accelerate
    args:
      # 必填 - hosts 格式数据，provider 引用或内联文本
      hosts:
        - "provider:tunnel_hosts"

      # ── 以下均为可选 ──────────────────────────────

      # 应答 TTL（秒），默认 30
      ttl: 30

      # 默认拨测端口，默认 443
      probe_port: 443

      # 按完整域名覆盖拨测端口
      # probe_port_map:
      #   "app.example.com": 8443

      # 单次拨测超时（秒），默认 1
      probe_timeout: 1

      # 拨测结果 LRU 缓存
      probe_cache_size: 1024
      probe_cache_ttl: 60
```

`tunnel-hosts.txt` 使用 hosts 格式（与 `hosts` 插件一致），一行一个完整域名，
可同时含 v4/v6 地址：

```
# 域名 地址1 地址2 ...
gitlab.example.com 1.2.3.4
app.example.com 5.6.7.8 2408:aaaa::1
```

## 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|:----:|:----:|------|
| `hosts` | `[]string` | 是 | - | hosts 格式数据，支持 `provider:` 引用与内联文本；**key 必须是完整域名（精确匹配）** |
| `ttl` | `int` | 否 | 30 | A/AAAA 应答 TTL（秒） |
| `probe_port` | `int` | 否 | 443 | 默认 TCP 拨测端口 |
| `probe_port_map` | `map[string]int` | 否 | 无 | 按完整域名覆盖拨测端口 |
| `probe_timeout` | `int` | 否 | 1 | 单次拨测超时（秒） |
| `probe_cache_size` | `int` | 否 | 1024 | 拨测结果 LRU 缓存容量 |
| `probe_cache_ttl` | `int` | 否 | 60 | 拨测结果缓存秒数 |

## 执行逻辑

```
查询进入 tunnel_accelerate
  │
  ├─ qname 未命中 hosts → 透传
  │
  ├─ 命中 hosts → 按查询类型分派：
  │
  │   A / AAAA（对称处理，只探测本族 IP）：
  │     ├─ 本族有存活 IP → 返回存活 IP 记录（TTL = ttl）
  │     ├─ 本族全死/未配置，另一族有存活 → 空 NOERROR（本族抑制，
  │     │   防止穿透公网造成「内网 v4 + 公网 v6」混族）
  │     └─ 全部 IP 死亡 → 透传（整域回落公网，自动故障转移）
  │
  │   TYPE65 (HTTPS)：
  │     ├─ 任一端点存活 → 空 NOERROR（阻断 ECH 公钥，
  │     │   客户端以明文 SNI 连隧道 IP）
  │     └─ 全部死亡 → 透传（客户端正常获取公网 ECH）
  │
  └─ 其他 qtype → 透传
```

拨测实现：

- 并发拨测条目内所有 IP（`net.DialTimeout` TCP，连上即视为存活）
- 结果按 `ip:port` 缓存（LRU + TTL），缓存 TTL 决定故障切换/恢复的感知延迟
- 多端点域名逐 IP 探测，只返回存活 IP

## 典型用法：三级客户端分流

配合 `client_matcher`（URL path client_id，见 `docs/doh-path.md`）：

```yaml
plugins:
  - tag: match_client_accel
    type: client_matcher
    args:
      client_id: ["accel", "tunnel-cn"]   # 支持别名

  - tag: tunnel_sequence
    type: sequence
    args:
      exec:
        - if: match_client_accel
          exec:
            - exec: $tunnel_accelerate     # 命中并接管 → 结束；全死 → 穿透
        # ... 后续公网分流链路
```

客户端请求 `/dns-query/accel` 即启用隧道加速；查询未登记域名时自然穿透走公网。

## 注意事项

- `hosts` 的 key 是**精确完整域名**，不支持后缀/通配匹配；需要加速的每个主机名
  单独一行。登记、应答、拨测目标由同一个文件承担，不会出现列表与地址不同步。
- 放在 `cache` 类插件**之前**：cache 无按域名 TTL 覆盖，放后面会被缓存遮蔽
  健康翻转。
- 故障切换/恢复收敛 ≈ `probe_cache_ttl` + `ttl` + 客户端缓存，默认参数约 2 分钟。
- 拨测从 mosdns 本机发起，需保证本机到隧道端点的网络可达（隧道入口必须是公网可达地址）。
