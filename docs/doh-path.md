# DoH Path Client Distribution

## Concept

AdGuard Home 等 DNS 过滤软件支持在同一 DoH 端口上按 URL 路径区分客户端（不同客户端可走不同的上游/过滤规则）。mosdns-x 通过以下机制实现同等能力：

1. **HTTP 层自动提取** — 当 `url_path` 配置为 `/dns-query` 时，请求 `/dns-query/family` 自动将 `family` 写入请求元数据的 `clientID` 字段
2. **插件层匹配** — `client_matcher` 插件读取 `clientID` 进行匹配，配合 `if` 分支实现分流

不改 server 配置结构，不引入路由层，不影响不使用的配置。

## URL Path → clientID 规则

假设 `url_path: /dns-query`：

| 请求 path | clientIDs | 行为 |
|-----------|-----------|------|
| `/dns-query` | `[]`（空） | 走默认流程，不触发任何 `client_matcher` |
| `/dns-query/family` | `["family"]` | 可被 `client_matcher` 匹配 |
| `/dns-query/edu/cn` | `["edu", "cn"]` | 两个 ID 均可被分别匹配，或配合 `match_all` 同时匹配 |
| `/dns-query/a//b/` | `["a", "b"]` | 空段被忽略 |
| `/other` | — | 404（无关路径被拒绝） |

路径段数量不限。每个段会做 URL 解码：`/dns-query/a%2Fb` 中的 `%2F` 解码为 `/`，得到单个 ID `"a/b"`（不会被误拆成两个段）。

当 `url_path` 为空时，不执行任何提取，完全向后兼容。

## 匹配语义：ANY 与 match_all

`client_matcher` 默认是 **ANY** 语义：路径中的任意一个 ID 命中配置列表即匹配（与单 ID 时代行为一致）：

```yaml
# /dns-query/edu/cn 会命中（edu 命中）；/dns-query/other 不命中
- tag: is_edu
  type: client_matcher
  args:
    client_id: ["edu"]
```

设置 `match_all: true` 后变为 **ALL** 语义：配置列表中的每个 ID 都必须出现在路径中（路径可含额外 ID）：

```yaml
# 仅当路径同时含 edu 和 cn 时命中：/dns-query/edu/cn ✓，/dns-query/edu ✗
- tag: is_edu_cn
  type: client_matcher
  args:
    client_id: ["edu", "cn"]
    match_all: true
```

`match_all` 与 `if` 表达式的等价关系、以及如何组合多个 matcher 构造复杂条件，见下文「复杂逻辑：if 表达式组合」。

## 配置示例

```yaml
plugins:
  # 定义两个客户端匹配器
  - tag: is_family
    type: client_matcher
    args:
      client_id: ["family"]

  - tag: is_adult
    type: client_matcher
    args:
      client_id: ["adult"]

  # 多 ID 组合：路径同时含 edu 与 cn 才命中
  - tag: is_edu_cn
    type: client_matcher
    args:
      client_id: ["edu", "cn"]
      match_all: true

  # 客户端 A 的上游
  - tag: forward_family
    type: forward
    args:
      upstream: "https://dns-family.example/dns-query"

  # 客户端 B 的上游
  - tag: forward_adult
    type: forward
    args:
      upstream: "https://dns-adult-filter.example/dns-query"

  # 默认上游
  - tag: forward_default
    type: forward
    args:
      upstream: "https://dns-public.example/dns-query"

  # 主执行链：按 clientID 分流
  - tag: main_seq
    type: sequence
    args:
      exec:
        - if: is_family
          exec: forward_family
        - if: is_adult
          exec: forward_adult
        - if: is_edu_cn
          exec: forward_edu_cn
        - exec: forward_default

servers:
  - exec: main_seq
    listeners:
      - protocol: https
        addr: :443
        cert: /path/to/cert.pem
        key: /path/to/key.pem
        url_path: /dns-query
```

同一端口上即可响应：

```
curl -H "Accept: application/dns-message" 'https://example.com/dns-query?dns=...'     # 默认
curl -H "Accept: application/dns-message" 'https://example.com/dns-query/family?dns=...'  # family
curl -H "Accept: application/dns-message" 'https://example.com/dns-query/adult?dns=...'   # adult
curl -H "Accept: application/dns-message" 'https://example.com/dns-query/edu/cn?dns=...'  # edu+cn
```

## 复杂逻辑：if 表达式组合

`if:` 接受 **govaluate 布尔表达式**，表达式的变量就是已注册 matcher 的 tag，支持 `&&`（且）、`||`（或）、`!`（非）和括号任意嵌套。因此不必为每种组合定义专门 matcher，用多个"原子 matcher"（单 ID 或 `match_all` 的 `client_matcher`，以及 IP/域名等任意 matcher）即可构造任意复杂条件：

```yaml
plugins:
  # 原子 matcher：每个 ID 一个
  - tag: is_edu
    type: client_matcher
    args:
      client_id: ["edu"]
  - tag: is_cn
    type: client_matcher
    args:
      client_id: ["cn"]
  - tag: is_family
    type: client_matcher
    args:
      client_id: ["family"]

# 组合使用（在 sequence 的 exec 里）：
- if: is_family && is_private_ip        # 内网且 family → 走 family 上游
  exec: forward_family
- if: is_edu || is_cn                   # edu 或 cn 任一命中
  exec: forward_edu_or_cn
- if: !is_family                        # 非 family 客户端
  exec: forward_non_family
- if: (is_edu && is_cn) || is_family    # 任意嵌套
  exec: forward_complex
```

注意：表达式中的 matcher tag 需以字母、数字、下划线命名（govaluate 变量名规则），否则无法作为变量引用。

### 与 match_all 的关系（共存）

`match_all` 与 `if` 表达式是**等价简写**关系，可按习惯混用：

| 写法 | 等价于 |
|------|--------|
| `client_id: ["edu", "cn"]`（默认 ANY） | `if: is_edu \|\| is_cn` |
| `client_id: ["edu", "cn"], match_all: true` | `if: is_edu && is_cn` |

- 高频、固定的组合 → 用 `match_all` 内联，少定义 tag、配置短
- 否定、跨 matcher 嵌套、一次性复杂判断 → 用 `if:` 表达式组合原子 matcher
- 两种 matcher 都可以继续被 `if:` 表达式引用组合（如 `if: is_edu_cn && !is_family`）

## 实现原理

- `pkg/query_context/context.go` — `RequestMeta` 新增 `clientIDs []string` 字段，提供 `SetClientIDs` / `GetClientIDs`（保留 `GetClientID` 返回第一个 ID，向后兼容）
- `pkg/server/http_handler/handler.go` — `ServeHTTP()` 中 URL path 前缀匹配后，将路径后缀按 `/` 拆分为多个 `clientID`（优先使用 `RawPath` 分割再逐段解码，避免 `%2F` 被误拆）
- `pkg/matcher/elem/str.go` — 通用字符串匹配器
- `plugin/matcher/client_matcher/` — `client_matcher` 插件，匹配 `qCtx.ReqMeta().GetClientIDs()`，支持 `match_all` 选项
- `plugin/executable/adg_cache/` — 缓存键使用完整 ID 列表（`/` 连接），避免不同 ID 组合串缓存

## 跨节点转发：client_id 透传

多节点部署时，边缘节点可用 `adg_forward` 的 `client_id_passthrough` 开关把
本机收到的 clientIDs 动态拼接到出站 URL path，中枢节点无需任何改动即可按
同样语义路由：

```
客户端 → 边缘: /dns-query/accel/international
边缘   → 中枢: https://hub:4215/dns-query/accel/international
```

tag 集合任意组合、顺序无关，无需为组合枚举上游；详见
[`adg_forward`](./plugins/adg_forward.md#client_id-透传多节点转发) 与
[`scenarios/hub-edge.md`](./scenarios/hub-edge.md)。
