# lan-relay —— Windows 11 局域网中转网关

接收同一无线局域网内的设备流量，全部经本机**有线 PPPoE 宽带拨号适配器**转发到互联网。

```
[手机等设备]                       [Windows 11 本机]                 [互联网]
Clash Meta for Android  ──WLAN──▶  lan-relay.exe        ──PPPoE──▶  校园网/宽带
  全局代理模式                      监听 WLAN IP:7890                 校园网 PPP 适配器
  server=本机IP                    (SOCKS5 + HTTP 混合)              (IP_UNICAST_IF 强制绑定出口)
```

- 手机端开启 Clash Meta for Android **全局模式**，代理指向本机 → 本程序是它的上游
- 本程序收到的所有 TCP / UDP 流量**强制从 PPPoE 拨号接口出站**（不受路由表 metric 影响），并使用宽带侧 DNS 做远程解析
- 应用层代理方案：无需开启 Windows 的 IP 路由（IPEnableRouter）、无需配置 NAT/ICS、不改路由表，程序退出零残留

---

## 快速开始

### 本机（Windows 11）

1. 确认 WLAN 已连入局域网、有线宽带（PPPoE）已拨号成功
2. 双击 `start-relay.bat`（自动申请管理员权限以添加防火墙放行规则），或直接运行 `lan-relay.exe`
3. 启动日志会打印关键信息：

```
代理入口: 192.168.25.177:7890（SOCKS5 + HTTP 混合，UDP=true）
状态页: http://192.168.25.177:9090/    Clash 配置下载: http://192.168.25.177:9090/clash.yaml
```

同时会在程序目录自动生成 `clash-android.yaml`（已填入本机 WLAN IP）。

### 手机端（Clash Meta for Android）

1. 手机连入**同一 WLAN**，浏览器打开 `http://<本机IP>:9090/clash.yaml` 下载配置（或把 `clash-android.yaml` 文件传到手机导入）
2. 在 Clash Meta for Android 中导入该配置并启动 VPN
3. 切换到**全局（Global）模式** —— 配置本身无任何规则，`mode: global` + `MATCH,PC-Relay` 双保险，所有流量直达本机

> 配置要点：代理类型 `socks5`、`udp: true`（支持 UDP 应用与 QUIC），DNS 上游 `223.5.5.5#PC-Relay` 也经中转代理送出，fake-ip 模式下域名原样穿过隧道由本机解析。

---

## 配置文件（relay-config.yaml）

```yaml
listen: auto        # 入站适配器：auto（优先 WLAN）/ 适配器名 / ifIndex / IP
listen_port: 7890   # 代理端口（SOCKS5 与 HTTP 混合，按首字节嗅探）
admin_port: 9090    # 状态页端口，0 禁用
wan: auto           # 出站适配器：auto（优先 PPP 拨号适配器）/ 适配器名 / ifIndex
udp: true           # SOCKS5 UDP 中转（DNS、QUIC、游戏）
dns_servers: []     # 出站 DNS：空=宽带适配器系统 DNS > 内置 223.5.5.5/119.29.29.29
allow_cidrs: []     # 客户端来源白名单，空=不限制
auth:               # 代理认证：默认无认证；同 WLAN 有他人时建议开启
  username: ""
  password: ""
quic_block: false   # true 时丢弃 UDP 443，迫使客户端回落 TCP
poll_secs: 5        # 适配器轮询间隔（监测重拨换 IP、WLAN 掉线重连）
log_file: ""        # 日志文件，空=仅控制台
```

命令行：`lan-relay.exe -gen-config`（写默认配置）· `-config <路径>`（指定配置）· `-version`

---

## 工作原理

1. **适配器发现**（`internal/netmon`）：通过 `GetAdaptersAddresses` 枚举适配器。入站自动选择有 RFC1918 私网 IPv4 的非 PPP 适配器（优先 WLAN 类名称）；出站自动选择 **IfType=23 的 PPP 适配器**（即宽带拨号）。每 5 秒轮询，PPPoE 重拨换 IP、WLAN 掉线重连都会自动跟随，监听器与出站绑定自动重建。
2. **出口强制绑定**（`internal/bind`）：每个出站 socket 通过 `IP_UNICAST_IF(31)` / `IPV6_UNICAST_IF(31)` 绑定 PPP 接口的 ifIndex（IPv4 需网络字节序），并以 PPP IP 作为 LocalAddr 双保险。即使 WLAN 侧也有一条默认路由（本机实测 metric 26 vs 4250），出站也一定走宽带。
3. **混合端口**（`internal/mixed`）：单端口同时服务 SOCKS5（`0x05` 开头）与 HTTP 代理，Clash 用 SOCKS5，浏览器等可直接填 HTTP 代理。
4. **SOCKS5**（`internal/socks5`）：RFC1928 CONNECT + UDP ASSOCIATE，可选 RFC1929 认证。UDP 会话按「客户端地址 + 目标白名单」过滤回包，120 秒空闲回收，TCP 控制连接断开即拆除。
5. **DNS**（`internal/resolver`）：域名经绑定了宽带接口的解析器（使用宽带侧系统 DNS，如 114.114.114.114 / 119.29.29.29）远程解析，带 60 秒缓存。
6. **防火墙**（`internal/firewall`）：以管理员运行时自动添加 `remoteip=localsubnet` 限内网放行规则；未提权时打印手动命令。

---

## 验证方法

```bash
# 出口 IP 应与「本机直连」一致（即宽带的公网出口），而非 WLAN 热点的出口
curl -s http://myip.ipip.net
curl -s --socks5-hostname <本机IP>:7890 http://myip.ipip.net
curl -s -x http://<本机IP>:7890 http://myip.ipip.net

# UDP 中转（SOCKS5 UDP ASSOCIATE + DNS 查询）
relayprobe.exe -proxy <本机IP>:7890 -mode udp -domain www.baidu.com
# TCP 隧道
relayprobe.exe -proxy <本机IP>:7890 -mode tcp -host myip.ipip.net -port 80

# 确认出站连接挂在 PPP 适配器上（下载期间执行；LocalAddress 应为宽带 IP）
netstat -ano | grep <lan-relay的PID> | grep ESTABLISHED
```

本项目已完成的自测结果（2026-09-12，实测环境：WLAN ifIndex 12 / 192.168.25.177，PPPoE「校园网」ifIndex 70 / 10.200.126.18）：

- SOCKS5(HTTP)、SOCKS5(HTTPS CONNECT)、HTTP 代理 三种路径出口 IP 均为 `183.234.253.65`，与本机直连一致
- UDP 中转 DNS 查询 `www.baidu.com` 返回 3 条 A 记录
- `netstat` 证实出站连接 LocalAddress 为 `10.200.126.18`（PPP 适配器）

---

## 故障排查

| 现象 | 处理 |
| --- | --- |
| 启动时「出站适配器未就绪」 | 先完成宽带拨号；或配置 `wan: 适配器名` 显式指定 |
| 启动时「入站适配器未就绪」 | WLAN 未连接或未取得私网 IPv4；或配置 `listen: WLAN` |
| 手机连不上代理 | 防火墙规则未放行（用 `start-relay.bat` 管理员运行一次）；确认手机与本机同一网段 |
| 能连上但无网络 | 看日志里 CONNECT 报错：宽带是否欠费/被限；部分站点被校园网屏蔽属出口限制，与本程序无关 |
| 某些应用不走代理 | Clash 需处于全局模式；UDP 应用需配置 `udp: true`（默认已开） |
| 多个候选出口报错 | 配置 `wan:` 显式指定适配器名 |

---

## 构建

```bash
go build -trimpath -ldflags "-s -w" -o lan-relay.exe .
go build -o relayprobe.exe ./cmd/relayprobe
go test ./...        # 单元测试（协议解析、适配器选择、中转、YAML 合法性）
```

依赖仅 `golang.org/x/sys`（Windows API）与 `gopkg.in/yaml.v3`（配置），Windows 10/11 x64 可直接运行，无需安装运行库。

## 目录结构

```
main.go                    程序组装、监听管理、防火墙、信号处理
internal/config/           配置加载与默认值
internal/netmon/           适配器发现/选择/轮询（纯逻辑 + Windows 枚举）
internal/bind/             IP_UNICAST_IF 出站接口绑定
internal/resolver/         绑定出口的 DNS 解析 + 缓存
internal/socks5/           SOCKS5 服务端（CONNECT + UDP ASSOCIATE）
internal/httpproxy/        HTTP 代理（CONNECT + absolute-form）
internal/mixed/            单端口协议嗅探分发
internal/relay/            双向流拷贝（缓冲池、统计、半关闭）
internal/admin/            状态页 + /clash.yaml 下载
internal/clashconf/        Clash 配置生成
internal/firewall/         防火墙规则自检与添加
cmd/relayprobe/            TCP/UDP 全链路探测工具
clash-android.yaml         手机端配置（启动时自动生成/更新）
```
