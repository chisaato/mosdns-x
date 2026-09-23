# edns_client_id

通过私有 EDNS0 option（默认 code 65002）在 DNS 报文中携带客户端身份 tag 列表，
作为 URL path（[`doh-path.md`](../doh-path.md)）之外的第二条机器间身份信道。

## 背景

多节点架构中，client_id 经 URL path 只能作用于 DoH/DoQ 链路。EDNS0 option 则
随报文本身传播，**任意传输（UDP/TCP/DoT/DoH/DoQ）通用**。option code 65001-65534
是私有实验段（类比 Private ASN），双方节点均为自家 mosdns 时即为合法约定：
65001 已被 dnsmasq MAC（见 [`mac_matcher`](mac_matcher.md)）占用，本插件默认用
**65002**。

身份模型：path 与 EDNS 双通道都汇入 `RequestMeta.clientIDs`（并集去重），下游
的 `client_matcher`、`if` 表达式、`adg_cache` 缓存键全部源无关，无需感知身份来
自哪条通道。

## Wire 格式

单个 option 内 TLV 列表（非重复 option code）：

```
OPTION-CODE:  65002
OPTION-DATA:  [u8 长度][tag UTF-8 字节] × N
```

- 写端排序 + 去重（wire 规范形，可对比可测试）
- 单 tag ≤ 255 字节，总 data ≤ 512 字节，超出部分丢弃并记 warn（不使查询失败）
- 读端容忍畸形：截断即停，已解析部分生效，绝不 panic

## 配置

```yaml
plugins:
  # 读端：中枢链路最顶部（先于 adg_cache，保证缓存键含 EDNS 来源 tag）
  - tag: edns_client_id_read
    type: edns_client_id
    args:
      mode: read
      # option_code: 65002

  # 写端：边缘节点转发中枢之前
  - tag: edns_client_id_write
    type: edns_client_id
    args:
      mode: write

  # 剥离端：公网出口不变式
  - tag: edns_client_id_strip
    type: edns_client_id
    args:
      mode: strip
```

## 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|:----:|:----:|------|
| `mode` | `string` | 是 | - | `read` / `write` / `strip` |
| `option_code` | `int` | 否 | 65002 | EDNS0 option code（私有段） |

## 执行逻辑

| mode | 行为 |
|------|------|
| `read` | 读取本 code 全部条目 → TLV 解析 → 并入 `RequestMeta.clientIDs`（与现有值并集去重）→ **从报文移除本 code 条目**（防外泄）；其他 option（ECS 等）原样保留 |
| `write` | 把 `RequestMeta.clientIDs` 排序去重后编码写入；已存在同 code 旧条目则替换；meta 为空则不改报文 |
| `strip` | 仅从报文移除本 code 条目，不改 meta |

三模式均**永不拦截查询**，执行后放行链路。只操作查询报文，不碰应答。

## 典型部署点位

```
边缘节点                                    中枢节点
────────                                    ────────
default_sequence:                           default_sequence:
  hosts → ecs                                 edns_client_id_read   ← 读+并入+剥离
  adg_filter → adg_cache                      hosts → ecs
  ├─ if 加速路由域:                           ... 加速分支 / outdoor ...
  │    edns_client_id_write  ← meta→报文      split_forward:
  │    hub(转发中枢)                            edns_client_id_strip ← 出口不变式
  └─ split_forward:                            cn / 海外
       edns_client_id_strip  ← 出口不变式
       cn / 海外
```

**公网出口不变式**：所有 `split_forward` 顶部放 strip——任何未来新增分支忘记
清洗，出公网前也会被兜住；中枢 read 端的即时剥离与之构成双保险。

与 `adg_forward` 的 `client_id_passthrough`（path 通道，见
[`hub-edge.md`](../scenarios/hub-edge.md)）可单用可并用：双载同一 tag 集合时
中枢并集去重，幂等无冲突。

## 注意事项

- EDNS0 option 语义为 hop-by-hop（RFC 6891），中间第三方递归器可能剥离未知
  option——本信道适用于**两端均为自家节点**的链路；面向外部标准客户端的入口
  仍用 URL path
- tag 建议保持 `[a-z0-9-_]` 字符集以与 path 语法互换；TLV 格式本身不限制字节
- 身份属 bearer claim（与 path 同级信任）：如需收紧，中枢可用 `client_ip`
  matcher 门控读端所在分支
