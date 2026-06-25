# mosdns-x AGENTS.md

## 项目结构

- `main.go` — 入口；blank import `plugin` 和 `tools` 触发插件自注册
- `coremain/` — 框架核心：配置加载、插件注册（`register.go`）、服务生命周期
- `plugin/` — **本 fork 重点修改目录**
  - `plugin/enabled_plugin.go` — 所有插件的空白导入注册表，**新增插件必须添加到此文件**
  - `plugin/executable/` — 23 个可执行插件（cache, forward, ecs, hosts, nftset 等）
  - `plugin/matcher/` — 2 个匹配器插件（`query_matcher`, `response_matcher`）
- `pkg/` — 共享库，匹配器实现位于 `pkg/matcher/`（domain, netlist, elem, macaddr 等）
- `pkg/executable_seq/` — 核心执行引擎接口（`Executable`, `Matcher`, 序列/并行/回退等）

## 插件开发要点

- 每个插件在其 `init()` 中调用 `coremain.RegNewPluginFunc(PluginType, Init, argsFactory)` 完成注册
- 插件 `type` 字符串（如 `"query_matcher"`、`"cache"`）对应 YAML 配置 `plugins[].type`
- 插件参数通过 `yaml` tag 反序列化，支持 `mapstructure` 弱类型转换
- 实现 `coremain.ExecutablePlugin` 接口（可执行）或 `coremain.MatcherPlugin` 接口（匹配器）
- 新增插件后必须在 `plugin/enabled_plugin.go` 添加 blank import
- `plugin/enabled_plugin_test.go` 可验证所有插件 `init()` 正常执行：`go test ./plugin/`

## 本 fork 自定义改动

- **MAC 地址匹配**: 新增 `pkg/matcher/macaddr/` MAC 地址匹配器，`query_matcher` 新增 `mac_address` 配置字段，用于匹配 DNS 请求中 dnsmasq 附加的客户端 MAC 地址
- **Docker 构建**: 已恢复（`Dockerfile` + `build-image.yml`）

## 合并上游更改

`upstream` 指向 `github.com/pmkol/mosdns-x`。需要合并时：`git fetch upstream && git merge upstream/main`。

## 构建与测试

| 命令 | 用途 |
|------|------|
| `go build -o mosdns main.go` | 编译 |
| `go test ./...` | 全部测试 |
| `go test ./plugin/` | 验证插件注册 |
| `gofmt -w .` / `goimports -w .` | 格式化（local prefix: `github.com/pmkol/mosdns-x`） |
| `docker build -t mosdns-x .` | Docker 构建 |

CI 仅执行 `go build`，不包含 lint/typecheck/test 步骤。

## 配置结构

YAML 配置，`mosdns start -c config.yaml` 启动。配置段：
`log`, `include`, `data_providers`, `plugins`, `servers`, `api`, `security`

支持 `include` 多文件递归合并（最大深度 8）。

```yaml
plugins:
  - tag: my_matcher
    type: query_matcher
    args:
      domain:
        - "example.com"
        - "provider:my_domain_list"
      mac_address:
        - "aa:bb:cc:dd:ee:ff"
  - tag: my_cache
    type: cache
    args:
      size: 10000
```

## CI/CD

- `test.yml` — push/PR 触发，仅 `go build` 编译验证
- `build-image.yml` — main 分支或 `v*` tag 推送时构建 Docker 镜像 → ghcr.io
- `release.yml` — 手动 `workflow_dispatch` 触发，跨平台编译 + ZIP 打包 + GitHub Release
