# mac_matcher

匹配 DNS 查询中 dnsmasq 附加的客户端 MAC 地址。

dnsmasq (OpenWrt) 通过 EDNS0 option code 65001 将请求客户端的 MAC 地址注入 DNS 查询。
`mac_matcher` 从查询的 EDNS0 选项中提取 MAC 地址，与配置的 MAC 列表做精确匹配。

## 配置

```yaml
plugins:
  - tag: my_mac_match
    type: mac_matcher
    args:
      mac_address:
        - "aa:bb:cc:dd:ee:ff"
        - "11:22:33:44:55:66"
        - "provider:my_mac_list"
```

## 参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `mac_address` | `[]string` | MAC 地址列表，支持固定值和 `provider:` 引用 |

MAC 地址格式为 6 字节冒号分隔的十六进制字符串（大小写不敏感），如 `aa:bb:cc:dd:ee:ff`。

`provider:` 前缀引用 `data_providers` 中声明的数据源，支持从文件加载和热更新。

## 匹配逻辑

```
收到 DNS 查询
  ├─ EDNS0 option code 65001 不存在 → 不匹配 (返回 false)
  └─ EDNS0 option code 65001 存在 → 提取 Data 作为 MAC
       ├─ MAC 命中 mac_address 列表 → 匹配 (返回 true)
       └─ MAC 未命中 → 不匹配 (返回 false)
```

## 内置预设匹配器

| 标签 | 说明 |
|------|------|
| `_has_mac_addr` | 检查查询是否携带了 dnsmasq 附加的 MAC 地址（EDNS0 option 65001），不关心 MAC 的具体值。返回 `true` 当且仅当 65001 选项存在且包含合法 MAC。 |

典型用法：配合 `mac_matcher` 实现"有 MAC 但不在白名单 → 走 A 上游，其余走 B 上游"。

```yaml
- if: "_has_mac_addr && !match_my_whitelist"
  exec:
    - upstream_for_others
    - _return
- exec: upstream_for_whitelisted_or_no_mac
```

## 典型用法

配合 `sequence` 实现"按 MAC 地址走不同上游"：

```yaml
plugins:
  - tag: match_my_laptop
    type: mac_matcher
    args:
      mac_address:
        - "aa:bb:cc:dd:ee:ff"

  - tag: match_other_devices
    type: mac_matcher
    args:
      mac_address:
        - "provider:iot_mac_list"

  - tag: main_sequence
    type: sequence
    args:
      - matches: match_my_laptop
        exec: my_fast_upstream
      - matches: match_other_devices
        exec: iot_blocking_upstream
      - exec: default_upstream
```

## 数据来源

```yaml
data_providers:
  iot_mac_list:
    file: ./data/iot_macs.txt
```

`iot_macs.txt` 每行一个 MAC 地址，空行和 `#` 开头的行为注释：

```
# 客厅设备
aa:bb:cc:dd:ee:ff
11:22:33:44:55:66

# 卧室设备
77:88:99:aa:bb:cc
```
