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

- **MAC 地址匹配**: 新增 `plugin/matcher/mac_matcher/` 独立匹配器插件（`type: mac_matcher`），从 EDNS0 option code 65001 中提取 dnsmasq (OpenWrt) 附加的客户端 MAC 地址并匹配。核心逻辑位于 `pkg/matcher/macaddr/`（匹配器 + `ExtractFromMsg()` 提取函数）。
- **Docker 构建**: 已恢复（`Dockerfile` + `build-image.yml`）

### 减少上游合并冲突的设计原则

fork 专属代码应集中在新文件或新包中，避免修改上游已有文件。涉及上游文件的改动应在验证可行后尽量还原：

| 上游文件 | 改动方式 |
|----------|----------|
| `pkg/dnsutils/`, `pkg/matcher/msg_matcher/` 等 | 不修改，提取逻辑到 `pkg/matcher/macaddr/` 自有包中 |
| `plugin/matcher/query_matcher/` | 不修改，拆分出独立 `mac_matcher` 插件 |
| `plugin/enabled_plugin.go` | 仅添加 blank import（一目了然的单行） |

## 合并上游更改

`upstream` 指向 `github.com/pmkol/mosdns-x`。

**推荐使用 rebase 而非 merge**：`git merge` 会产生 merge commit，且导致 fork 本地与上游「同内容不同 hash」的 commit 共存，GitHub 会据此显示 "N commits behind"。

```bash
# 正确做法：rebase 到上游最新
git fetch upstream
git rebase upstream/main

# 如果有未提交的改动先暂存
git stash
git rebase upstream/main
git stash pop

# rebase 完成后强制推送（fork 专属分支）
git push --force-with-lease origin main
```

**rebase 后 GitHub 的 behind 计数归零**，因为 fork 的 commit DAG 以 upstream 最新提交为线性祖先。同名变更的 commit 会被自动跳过。

如果 rebase 中途出现冲突且确认某 commit 的内容已被上游覆盖，用 `git rebase --skip` 跳过。

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
  - tag: my_mac_match
    type: mac_matcher
    args:
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
