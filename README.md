# mosdns-x 自用改版

## 增加特性

- mac 地址匹配,用于适配 dnsmasq 的添加请求者 mac 地址功能.
   - `_has_mac_addr` 预设匹配器: 判断查询是否携带 MAC (EDNS0 option 65001),不关心具体值.

- 恢复 Docker 构建,我就要用 Docker 部署.
