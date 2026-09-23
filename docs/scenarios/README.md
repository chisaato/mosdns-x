# 部署情境

> 公网 DNS 节点部署的实际使用情境索引：各情境的解析流程、配置要点与边界行为。
> 标注 **[待补充]** 的部分需要结合实际部署信息完善。

## 全景

一台公网 DNS 服务器同时服务三类客户端，按 DoH/DoQ URL path 中的
client_id 区分（机制见 [`docs/doh-path.md`](../doh-path.md)）：

| 客户端 | 请求 path | 身份 | 加速策略 | 情境文档 |
|--------|-----------|------|----------|----------|
| 内网/国内设备 | `/dns-query` | 无 tag | pdns 内网加速（K3S 服务） | [internal-accelerate](./internal-accelerate.md) |
| 隧道加速客户端 | `/dns-query/accel` | `accel` | 国内隧道（拨测 gate + hosts 应答） | [tunnel-accelerate](./tunnel-accelerate.md) |
| 海外/有梯子设备 | `/dns-query/outdoor` | `outdoor` | 直接公网（Cloudflare，ECH 完整） | [outdoor](./outdoor.md) |
| 多节点部署 | — | 中枢/边缘分层 | 等级跨节点传播与数据源收敛 | [hub-edge](./hub-edge.md) |

服务器组件：

```
客户端 ──DoH/DoQ :4215 (dns.example.com)──▶ mosdns
                                            ├─▶ pdns-auth 127.0.0.1:2653
                                            │     ▲ RFC2136 DNS Update
                                            │     └─ K3S external-dns（多集群多 owner）
                                            ├─▶ 国内 DoH（cn 分流）
                                            └─▶ 海外加密 DoH
```

- **pdns** 是 K3S external-dns 的写入目标：服务部署 → 记录出现；服务删除 → 记录被清理。
  **记录存在性 = "服务已在内网部署"的真理来源**。
- external-dns 以 `a-<name>` / `aaaa-<name>` TXT 记录分别跟踪 A/AAAA 所有权，
  单栈集群只会写单族记录。gate 判定必须看实际 A/AAAA 存在性（库中存在仅有 TXT 无
  地址记录的孤儿条目）。

## 统一模型：gate → 答案源 → ECH 策略

两条加速链路（pdns 内网加速 / 国内隧道）共享同一语义框架：

| | 内网加速（无 tag） | 隧道加速（accel） |
|---|---|---|
| gate | pdns 记录存在性 | 隧道端点 TCP 拨测存活 |
| 答案源 | forward_pdns | hosts 文件静态映射 |
| ECH 策略 | gate 命中 → 空 TYPE65 | gate 命中 → 空 TYPE65 |
| gate 未命中 | 落回公网 | 落回公网（自动故障转移） |

### 分族语义（防混族泄漏）

gate 以 **域** 为单位接管，以 **族（A/AAAA）** 为单位应答：

| 查询族状态 | 应答 | 客户端行为 |
|---|---|---|
| 本族存活 | 返回 gate 记录 | 使用该族 |
| 本族缺失/死亡，但另一族存活 | 空 NOERROR（本族抑制） | 只用存活族，**绝不回落公网该族** |
| 全部族死亡 | 放行公网（仅隧道拨测场景） | 整域回落 Cloudflare，ECH 完整 |

抑制空应答的目的：避免「内网 v4 + 公网 v6」这类混族解析——单栈集群只推 A 时，
若 AAAA 穿透到公网，客户端会拿到 Cloudflare 的 v6，绕过内网加速。

ECH（TYPE65）的阻断与 A/AAAA 使用**同一个 gate**：任一族存活即阻断（客户端拿
不到 ECH 公钥，以明文 SNI 连内网/隧道 IP）；全部死亡则放行 TYPE65（客户端正常
获得 Cloudflare 的 ECH 配置）。

## 边界情境速查

| 情境 | 行为 | 详见 |
|------|------|------|
| 单栈 K8S 只推 A | AAAA 返回空 NOERROR，客户端只用内网 v4；公网 v6 不泄漏 | [internal-accelerate](./internal-accelerate.md) |
| 单栈隧道（hosts 只配 v4） | 同上对称 | [tunnel-accelerate](./tunnel-accelerate.md) |
| 隧道端点全挂 | accel 客户端整域回落 Cloudflare；恢复后约 2 分钟自动切回 | [tunnel-accelerate](./tunnel-accelerate.md) |
| pdns 中服务已删（NXDOMAIN） | 无 tag 客户端回落公网，走 Cloudflare | [internal-accelerate](./internal-accelerate.md) |
| pdns 孤儿 TXT（无地址记录） | 不构成 gate，正常回落公网 | [internal-accelerate](./internal-accelerate.md) |
| v6-only 集群 | ech_block 双族探测照常阻断 ECH | [internal-accelerate](./internal-accelerate.md) |

## 待补充（全局）

- [ ] 实际站点拓扑：除公网节点外的其他 mosdns/pdns 实例（如本地实例）及其与
      各情境的关系
- [ ] 多 owner 双集群是否需要差异化策略
- [ ] 服务器 config.yaml 实际改造后的完整样例（各情境文档先给片段）
