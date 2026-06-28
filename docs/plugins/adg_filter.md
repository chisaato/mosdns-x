# adg_filter — 广告域名拦截插件

## 简介

`adg_filter` 是一个 DNS 级广告/跟踪器域名拦截插件，使用 AdGuard 过滤列表语法。运行时使用 mosdns 域名 trie（SubDomainMatcher）匹配，无 urlfilter 运行时依赖。

## 两大来源

| 来源 | 字段 | 格式 | 加载方式 |
|------|------|------|----------|
| 过滤列表 | `block_lists` / `allow_lists` | `url:` value — `file://` 本地文件 或 `https://` 远程 | 下载/读取 → 去重 → 提取域名 → trie |
| Mosdns 原生源 | `block_provider` / `allow_provider` | `[]string`，同 `query_matcher` 域名语法 | `BatchLoadDomainProvider` 统一加载 |

**原生源语法**（同 `query_matcher` 的域名字段）：

```yaml
block_provider:
  - "provider:ads_dat"           # data_providers tag → 自动检测文件格式
  - "provider:ads_dat:ads"       # 指定 geosite tag 过滤
  - "domain:example.com"         # inline domain 语法
  - "custom-block-domain.com"    # 纯域名
```

两者自动合并到同一个 MatcherGroup，查询时先匹配过滤列表再匹配 provider。

## 配置示例

### 场景 1：纯 adblock list（本机测试）

```yaml
plugins:
  - tag: block_ads
    type: adg_filter
    args:
      block_lists:
        - url: file:///etc/mosdns/my_rules.txt   # 本地 adblock 文件
          id: 1
        - url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
          name: AdGuard DNS
          id: 2
      block_mode: nxdomain
      cache_dir: /var/cache/mosdns
      update_interval: 86400
```

### 场景 2：纯 provider 源（局域网生产）

```yaml
data_providers:
  - tag: ads_blob
    file: /etc/mosdns/ads.dat
    auto_reload: true
  - tag: my_allow
    file: /etc/mosdns/allowlist.txt
    auto_reload: true

plugins:
  - tag: block_ads
    type: adg_filter
    args:
      block_provider:
        - "provider:ads_blob:ads"   # .dat + geosite tag
      allow_provider:
        - "provider:my_allow"       # 纯文本域名列表
      block_mode: nxdomain
```

### 场景 3：混合（云服务器）

```yaml
data_providers:
  - tag: ads_blob
    file: /etc/mosdns/ads.dat
    auto_reload: true

plugins:
  - tag: block_ads
    type: adg_filter
    args:
      block_provider:
        - "provider:ads_blob:ads"             # .dat 主力
      block_lists:
        - url: file:///etc/mosdns/manual_rules.txt   # 手写 adblock 补充
          id: 99
      allow_lists:
        - url: file:///etc/mosdns/emergency_allow.txt
          id: 100
      block_mode: nxdomain
      cache_dir: /var/cache/mosdns
```

## 内存与性能

| 200w+ 域名 | 内存 | 启动时间 |
|-----------|------|---------|
| block_lists（text → trie） | 100-150 MB | 首次 10-20s，缓存 3-5s |
| block_provider（.dat → trie） | 25-40 MB | 2-5s |

- 所有域名最终进入 `SubDomainMatcher` trie，查询 O(label 数量)，与规则总数无关
- `cache_dir` 会缓存提取后的域名文本（`adg_filter_block.domains`），重启时跳过解析步骤

## 热重载

- `block_lists`：`update_interval` 定时重建，通过 DynamicMatcher 原子更新
- `block_provider`：data_providers `auto_reload: true` + fsnotify → DynamicMatcher 自动热更新
- 两者独立更新，互不影响，无需重启 mosdns

## CLI: `mosdns compile-ads`

从 mosdns 配置提取 `adg_filter` 插件的 `block_lists`，编译为 geosite `.dat` 文件。

```bash
mosdns compile-ads -c mosdns.yaml -o ads.dat            # 默认 tag=ads
mosdns compile-ads -c mosdns.yaml -f block_ads -o ads.dat  # 指定插件 tag
mosdns compile-ads -c mosdns.yaml -t category-ads -o ads.dat  # 指定 geosite tag
mosdns compile-ads -c mosdns.yaml -f my_filter -t gfw -o gfw.dat
```

## 参数参考

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `block_lists` | list | `[]` | 过滤列表：`url:` 值为 `file://`（本地）或 `https://`（远程） |
| `block_provider` | list | `[]` | `[]string`，同 query_matcher 域名语法 |
| `allow_lists` | list | `[]` | 允许列表 |
| `allow_provider` | list | `[]` | `[]string`，同 query_matcher 域名语法 |
| `block_mode` | string | `"nxdomain"` | `nxdomain` / `refused` / `zero_ip` / `custom_ip` |
| `blocking_ipv4` | string | `"0.0.0.0"` | custom_ip 模式的 IPv4 |
| `blocking_ipv6` | string | `"::"` | custom_ip 模式的 IPv6 |
| `update_interval` | int | `86400` | 后台刷新间隔（秒） |
| `cache_dir` | string | `""` | 缓存目录 |
