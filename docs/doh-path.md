# DoH Path Client Distribution

## Concept

AdGuard Home 等 DNS 过滤软件支持在同一 DoH 端口上按 URL 路径区分客户端（不同客户端可走不同的上游/过滤规则）。mosdns-x 通过以下机制实现同等能力：

1. **HTTP 层自动提取** — 当 `url_path` 配置为 `/dns-query` 时，请求 `/dns-query/family` 自动将 `family` 写入请求元数据的 `clientID` 字段
2. **插件层匹配** — `client_matcher` 插件读取 `clientID` 进行匹配，配合 `if` 分支实现分流

不改 server 配置结构，不引入路由层，不影响不使用的配置。

## URL Path → clientID 规则

假设 `url_path: /dns-query`：

| 请求 path | clientID | 行为 |
|-----------|----------|------|
| `/dns-query` | `""`（空） | 走默认流程，不触发任何 `client_matcher` |
| `/dns-query/family` | `"family"` | 可被 `client_matcher` 匹配 |
| `/dns-query/family/child` | `"family"` | 只取第一段路径 |
| `/other` | — | 404（无关路径被拒绝） |

当 `url_path` 为空时，不执行任何提取，完全向后兼容。

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
```

## 搭配其他匹配条件

`client_matcher` 可与其他匹配器组合，实现更精细的分流，例如按客户端 IP + clientID 组合判断：

```yaml
# 只有来自内网且 clientID 为 family 的请求才走 family 上游
- if: _and
  args:
    - tag: is_family
    - tag: is_private_ip
  exec: forward_family
```

## 实现原理

- `pkg/query_context/context.go` — `RequestMeta` 新增 `clientID` 字段
- `pkg/server/http_handler/handler.go` — `ServeHTTP()` 中 URL path 前缀匹配后提取路径后缀作为 `clientID`
- `pkg/matcher/elem/str.go` — 通用字符串匹配器
- `plugin/matcher/client_matcher/` — `client_matcher` 插件，匹配 `qCtx.ReqMeta().GetClientID()`
