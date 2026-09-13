// Package clashconf 生成可导入 Clash Meta for Android 的配置文件。
package clashconf

import (
	"fmt"
	"strings"
)

// ProxyName Clash 中本中转程序的代理节点名。
const ProxyName = "PC-Relay"

// Generate 生成配置：全局模式 + MATCH 兜底，不进行任何规则分流，
// 所有流量（含 DNS 上游）直接转发到本机代理端口。
func Generate(server string, port int, username, password string) string {
	var b strings.Builder
	b.WriteString("# 由 lan-relay 自动生成 —— Clash Meta for Android 配置\n")
	b.WriteString("# 全局模式：不做任何规则匹配，全部流量经本机（中转网关）出站\n")
	b.WriteString(fmt.Sprintf("# 生成时间见程序启动日志；导入后在「概况-全局」或代理页选择 %s\n\n", ProxyName))

	fmt.Fprintf(&b, "mixed-port: 7890\n")
	b.WriteString("allow-lan: false\n")
	b.WriteString("mode: global\n")
	b.WriteString("log-level: info\n")
	b.WriteString("ipv6: false\n")
	b.WriteString("unified-delay: true\n")
	b.WriteString("keep-alive-interval: 30\n\n")

	b.WriteString("dns:\n")
	b.WriteString("  enable: true\n")
	b.WriteString("  ipv6: false\n")
	b.WriteString("  enhanced-mode: fake-ip\n")
	b.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	b.WriteString("  fake-ip-filter:\n")
	b.WriteString("    - '*.lan'\n")
	b.WriteString("    - '+.local'\n")
	b.WriteString("    - '+.msftconnecttest.com'\n")
	b.WriteString("    - '+.msftncsi.com'\n")
	b.WriteString("  # DNS 上游查询也经中转代理送出（#PC-Relay 指定出站代理）\n")
	fmt.Fprintf(&b, "  nameserver:\n    - '223.5.5.5#%s'\n    - '119.29.29.29#%s'\n\n", ProxyName, ProxyName)

	b.WriteString("proxies:\n")
	fmt.Fprintf(&b, "  - name: %s\n", ProxyName)
	b.WriteString("    type: socks5\n")
	fmt.Fprintf(&b, "    server: %s\n", server)
	fmt.Fprintf(&b, "    port: %d\n", port)
	b.WriteString("    udp: true\n")
	if username != "" || password != "" {
		fmt.Fprintf(&b, "    username: %s\n", username)
		fmt.Fprintf(&b, "    password: %s\n", password)
	}
	b.WriteString("\n")

	b.WriteString("proxy-groups:\n")
	fmt.Fprintf(&b, "  - name: PROXY\n    type: select\n    proxies:\n      - %s\n\n", ProxyName)

	b.WriteString("rules:\n")
	fmt.Fprintf(&b, "  - MATCH,%s\n", ProxyName)
	return b.String()
}
