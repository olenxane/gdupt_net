// Package admin 提供状态页与 Clash 配置下载。
package admin

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"lanrelay/internal/clashconf"
	"lanrelay/internal/config"
	"lanrelay/internal/netmon"
	"lanrelay/internal/stats"
)

// Hub 状态服务。
type Hub struct {
	Version  string
	Start    time.Time
	Cfg      *config.Config
	Snapshot func() netmon.Snapshot
}

// Handler 返回状态服务路由。
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/status", h.statusJSON)
	mux.HandleFunc("/clash.yaml", h.clashYAML)
	return mux
}

func (h *Hub) index(w http.ResponseWriter, r *http.Request) {
	s := h.Snapshot()
	uptime := time.Since(h.Start).Round(time.Second)
	tpl := `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>LAN 中转网关</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,"Microsoft YaHei",sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 16px}table{border-collapse:collapse;width:100%;max-width:720px}
td,th{border:1px solid #334155;padding:8px 12px;text-align:left;font-size:14px}
th{background:#1e293b;width:220px}a{color:#7dd3fc}.ok{color:#4ade80}.bad{color:#f87171}
</style></head><body>
<h1>LAN 中转网关 v{{.Version}}</h1>
<table>
<tr><th>运行时长</th><td>{{.Uptime}}</td></tr>
<tr><th>入站（监听）适配器</th><td>{{if .LAN}}{{.LAN.Name}} · ifIndex {{.LAN.Index}} · {{.LANIP}}{{else}}<span class="bad">未就绪</span>{{end}}</td></tr>
<tr><th>出站（PPPoE）适配器</th><td>{{if .WAN}}{{.WAN.Name}} · ifIndex {{.WAN.Index}} · {{.WANIP}}{{else}}<span class="bad">未就绪（宽带未拨号？）</span>{{end}}</td></tr>
<tr><th>代理端口</th><td>{{.Port}}（SOCKS5 + HTTP 混合，UDP {{.UDPText}}）</td></tr>
<tr><th>活跃 TCP 隧道</th><td>{{.TCP}}</td></tr>
<tr><th>活跃 UDP 会话</th><td>{{.UDP}}</td></tr>
<tr><th>累计 TCP 连接</th><td>{{.Conns}}</td></tr>
<tr><th>上行流量（客户端→互联网）</th><td>{{.Up}}</td></tr>
<tr><th>下行流量（互联网→客户端）</th><td>{{.Down}}</td></tr>
<tr><th>Clash 配置下载</th><td><a href="/clash.yaml">/clash.yaml</a>（手机浏览器直接打开导入）</td></tr>
</table></body></html>`
	data := map[string]any{
		"Version":  h.Version,
		"Uptime":   uptime.String(),
		"LAN":      s.LAN,
		"WAN":      s.WAN,
		"LANIP":    ipStr(s.LANIP()),
		"WANIP":    ipStr(s.WANIP()),
		"Port":     h.Cfg.ListenPort,
		"UDPText":  map[bool]string{true: "开启", false: "关闭"}[h.Cfg.UDP],
		"TCP":      stats.TCPActive.Load(),
		"UDP":      stats.UDPActive.Load(),
		"Conns":    stats.ConnsTotal.Load(),
		"Up":       humanBytes(stats.BytesUp.Load()),
		"Down":     humanBytes(stats.BytesDown.Load()),
	}
	t := template.Must(template.New("i").Parse(tpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.Execute(w, data)
}

func (h *Hub) statusJSON(w http.ResponseWriter, r *http.Request) {
	s := h.Snapshot()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	udpState := "off"
	if h.Cfg.UDP {
		udpState = "on"
	}
	fmt.Fprintf(w, `{"version":%q,"uptime_seconds":%d,
"lan":{"name":%q,"index":%d,"ip":%q},
"wan":{"name":%q,"index":%d,"ip":%q},
"listen_port":%d,"udp":%q,
"tcp_active":%d,"udp_active":%d,"connections_total":%d,
"bytes_up":%d,"bytes_down":%d}`,
		h.Version, int64(time.Since(h.Start).Seconds()),
		adapterName(s.LAN), adapterIndex(s.LAN), ipStr(s.LANIP()),
		adapterName(s.WAN), adapterIndex(s.WAN), ipStr(s.WANIP()),
		h.Cfg.ListenPort, udpState,
		stats.TCPActive.Load(), stats.UDPActive.Load(), stats.ConnsTotal.Load(),
		stats.BytesUp.Load(), stats.BytesDown.Load())
}

func (h *Hub) clashYAML(w http.ResponseWriter, r *http.Request) {
	s := h.Snapshot()
	lip := s.LANIP()
	if lip == nil {
		http.Error(w, "入站适配器未就绪，无法生成配置", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=clash-android.yaml")
	_, _ = w.Write([]byte(clashconf.Generate(lip.String(), h.Cfg.ListenPort, h.Cfg.Auth.Username, h.Cfg.Auth.Password)))
}

func adapterName(a *netmon.Adapter) string {
	if a == nil {
		return ""
	}
	return a.Name
}

func adapterIndex(a *netmon.Adapter) int {
	if a == nil {
		return 0
	}
	return a.Index
}

func ipStr(ip interface{ String() string }) string {
	if ip == nil {
		return "-"
	}
	return ip.String()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
