# observability

可观测性集成插件。集 Prometheus 指标暴露 + dnstap FSTRM 输出于一体，用于跟踪查询统计、拦截率和日志归档。

## 配置

```yaml
plugins:
  - tag: obs
    type: observability
    args:
      # ── Prometheus 指标服务 ─────────────────────────────────────
      prometheus_listen: ":9090"         # 监听地址，空=不开 HTTP
      prometheus_path: "/metrics"        # URL 路径，默认 /metrics

      # ── dnstap FSTRM 输出（可选） ───────────────────────────────
      dnstap_socket: ""                  # unix socket 路径，空=不开
```

## 使用模式

### 简单模式 — 仅 Prometheus

```yaml
- tag: obs
  type: observability
  args:
    prometheus_listen: ":9090"
```

独立 HTTP 端口，不依赖 `api.http`。`curl :9090/metrics` 即可查看拦截率。

### 高级模式 — 同时输出 dnstap

```yaml
- tag: obs
  type: observability
  args:
    prometheus_listen: ":9090"
    dnstap_socket: /var/run/mosdns/dnstap.sock
```

Prometheus 指标照常暴露的同时，每笔查询以 FSTRM (Frame Stream) 协议写入 Unix socket，消费端接收后可送 ClickHouse 长期沉淀。

### 纯 dnstap（不需要 Prometheus）

```yaml
- tag: obs
  type: observability
  args:
    prometheus_listen: ""
    dnstap_socket: /var/run/mosdns/dnstap.sock
```

## Pipeline 位置

插件必须放在 sequence **最前面**，wrap 整条链路。这是因为 mosdns 的链式调用中，拦截插件（如 `adg_filter`）命中后 `return nil` 不调 next，排在后面的节点无法执行。

```yaml
- tag: main_seq
  type: sequence
  args:
    exec:
      - exec: obs               # ← 必须第一个，wrap 整条链路
      - exec: adg_block
      - exec: forward
```

执行流：

```
obs.Exec() 开始
  ├─ query_total++ / thread++
  ├─ ExecChainNode(ctx, qCtx, adg_block)
  │   ├─ 拦截命中 → AddMark → applyBlock → return nil
  │   └─ 未命中   → ExecChainNode(ctx, qCtx, forward) → 正常处理
  └─ 回到 obs
      ├─ HasMark → blocked_total++ / passed_total++
      ├─ latency / dnstap 输出
      └─ return err
```

支持在多个 sequence 中同时引用同一 `tag`。插件内置一次幂保护（`recordedMark`），同一笔查询只会被记录一次，不会重复计数。

## Prometheus 指标

插件使用独立的 `prometheus.NewRegistry()`，包含原厂输出 + 自定义指标：

| 指标名 | 类型 | 说明 |
|--------|------|------|
| `query_total` | Counter | 经过此观测器的总查询数 |
| `err_total` | Counter | 下游返回 error 的查询数 |
| `thread` | Gauge | 当前并发数 |
| `response_latency_millisecond` | Histogram | 响应延迟分布（ms） |
| `blocked_total` | Counter | 被拦截的查询数 |
| `passed_total` | Counter | 未被拦截的查询数 |

时间戳、go_goroutines、gc 等通用指标与 `api.http` 的 `/metrics` 输出一致。

拦截率计算：`blocked_total / (blocked_total + passed_total) × 100%`

## dnstap 输出

### 传输协议

- 协议：FSTRM (Frame Stream) over Unix Socket
- 内容类型：`protobuf:dnstap.Dnstap`
- 方向：单向（mosdns 写，消费端读）

### 消息结构

每条查询输出一条 `dnstap.Dnstap` protobuf 消息：

```
Dnstap {
  Type:    MESSAGE
  Message: {
    Type:            CLIENT_QUERY
    QueryTimeSec:    查询到达时间 (unix sec)
    QueryTimeNsec:   查询到达时间 (nsec)
    ResponseTimeSec: 响应完成时间 (unix sec)
    ResponseTimeNsec:响应完成时间 (nsec)
    SocketFamily:    INET
    SocketProtocol:  UDP
    QueryMessage:    DNS 查询报文 (wire format)
    ResponseMessage: DNS 响应报文 (wire format)
  }
  Extra: [1] 或 [0]   # 1=拦截, 0=放行
}
```

### 消费端示例（Go）

```go
import (
    "github.com/farsightsec/golang-framestream"
    dt "github.com/dnstap/golang-dnstap"
    "google.golang.org/protobuf/proto"
)

conn, _ := net.Dial("unix", "/var/run/mosdns/dnstap.sock")
r, _ := framestream.NewReader(conn, &framestream.ReaderOptions{
    ContentTypes: [][]byte{[]byte("protobuf:dnstap.Dnstap")},
})

for {
    frame, _ := r.ReadFrame()
    msg := &dt.Dnstap{}
    proto.Unmarshal(frame, msg)

    blocked := len(msg.Extra) == 1 && msg.Extra[0] == 1
    // INSERT INTO ClickHouse ...
}
```

### Extra 字段说明

| Extra 字节 | 含义 |
|:---------:|------|
| `[0]` | 放行（未被拦截） |
| `[1]` | 拦截（被 adg_filter 等插件标记） |

下游消费端可通过 `response_rcode` 进一步细化：NXDOMAIN(2)、REFUSED(5) 等。

## 替换 `metrics_collector`

新配置不需要 `metrics_collector`：

```yaml
# 之前
- exec: metrics_collector
- exec: adg_block
- exec: forward

# 之后（删掉 metrics_collector，用 obs 替代）
- exec: adg_block
- exec: forward
- exec: obs
```

原 `metrics_collector` 插件保留不动，与其他上游保持兼容。

## 与 `api.http` 的关系

`observability` 插件**不依赖** `api.http` 配置段。即使 `api` 段完全没有配置，Prometheus 指标和 dnstap 输出仍正常运作。
