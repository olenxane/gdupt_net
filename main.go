// lan-relay —— Windows 11 局域网中转网关。
//
// 接收同一 WLAN 内设备（Clash Meta for Android 全局代理）发来的
// SOCKS5/HTTP 代理流量，并将所有出站流量强制经有线 PPPoE 宽带拨号
// 适配器转发到互联网。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lanrelay/internal/admin"
	"lanrelay/internal/bind"
	"lanrelay/internal/clashconf"
	"lanrelay/internal/config"
	"lanrelay/internal/firewall"
	"lanrelay/internal/httpproxy"
	"lanrelay/internal/mixed"
	"lanrelay/internal/netmon"
	"lanrelay/internal/resolver"
	"lanrelay/internal/socks5"
)

func main() {
	exePath, _ := os.Executable()
	base := filepath.Dir(exePath)

	cfgPath := flag.String("config", filepath.Join(base, "relay-config.yaml"), "配置文件路径")
	genConfig := flag.Bool("gen-config", false, "写入默认配置文件后退出")
	showVersion := flag.Bool("version", false, "显示版本")
	flag.Parse()

	if *showVersion {
		fmt.Println("lan-relay", config.Version)
		return
	}
	if *genConfig {
		if err := config.WriteDefault(*cfgPath); err != nil {
			log.Fatalf("写入默认配置失败: %v", err)
		}
		log.Printf("已写入默认配置: %s", *cfgPath)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	setupLog(cfg.LogFile)
	log.Printf("=== LAN 中转网关 v%s ===", config.Version)
	log.Printf("配置文件: %s", *cfgPath)

	// 1. 适配器发现与监控（入站 WLAN / 出站 PPPoE）
	mon := netmon.New(cfg.Listen, cfg.WAN, time.Duration(cfg.PollSecs)*time.Second, netmon.FetchAdapters)
	go mon.Run()

	log.Printf("等待适配器就绪（入站: %s，出站: %s）…", cfg.Listen, cfg.WAN)
	if err := mon.WaitReady(2 * time.Minute); err != nil {
		log.Printf("[警告] %v —— 程序将继续运行，适配器就绪后自动生效", err)
	}
	printSnapshot(mon.Snapshot())

	// 2. 出站绑定与解析（用户配置 DNS > 适配器系统 DNS > 内置公共 DNS）
	out := &outbound{mon: mon}
	res := resolver.New(
		func() []net.IP {
			if ips := cfgIPs(cfg.DNSServers); len(ips) > 0 {
				return ips
			}
			return mon.Snapshot().DNSServers()
		},
		out.control,
		func() bool { return true }, // PPP 出站通常仅 IPv4，优先 A 记录
	)
	out.res = res

	// 3. 组装协议服务
	socksSrv := &socks5.Server{
		Dial:       out.dial,
		Resolve:    res.Lookup,
		UDPEnabled: cfg.UDP,
		NewEgress:  out.udpEgress,
		QUICBlock:  cfg.QUICBlock,
		AuthUser:   cfg.Auth.Username,
		AuthPass:   cfg.Auth.Password,
	}
	httpSrv := &httpproxy.Server{Dial: out.dial}

	hub := &admin.Hub{
		Version:  config.Version,
		Start:    time.Now(),
		Cfg:      cfg,
		Snapshot: mon.Snapshot,
	}

	// 4. 生成 Clash 配置文件（随适配器变化自动重写）
	mon.OnChange(func(old, new netmon.Snapshot) {
		writeClashConfig(base, cfg, new)
	})
	writeClashConfig(base, cfg, mon.Snapshot())

	// 5. 防火墙放行
	ensureFirewall(cfg)

	// 6. 启动监听（入站适配器 IP 变化时自动重建）
	quit := make(chan struct{})
	restart := make(chan struct{}, 1)
	mon.OnChange(func(old, new netmon.Snapshot) {
		if ipStr(old.LANIP()) != ipStr(new.LANIP()) {
			select {
			case restart <- struct{}{}:
			default:
			}
		}
	})
	go serveAll(cfg, hub, socksSrv, httpSrv, mon, restart, quit)

	// 7. 优雅退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("收到退出信号，正在关闭…")
	close(quit)
	mon.Stop()
	time.Sleep(300 * time.Millisecond)
	log.Println("已退出")
}

// outbound 出站拨号与 UDP 出口（全部绑定 PPPoE 接口）。
type outbound struct {
	mon *netmon.Monitor
	res *resolver.Resolver
}

// control 出站 socket 绑定回调（IP_UNICAST_IF）。
func (o *outbound) control(network, address string, c syscall.RawConn) error {
	idx := o.mon.Snapshot().WANIndex()
	if idx == 0 {
		return fmt.Errorf("出站适配器未就绪")
	}
	return bind.Control(idx)(network, address, c)
}

// dial 出站拨号：域名经绑定出站接口的 DNS 解析后，以绑定接口的拨号器连接。
func (o *outbound) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	s := o.mon.Snapshot()
	if s.WANIndex() == 0 {
		return nil, fmt.Errorf("出站适配器（宽带）未就绪")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("目标地址无效 %q: %w", addr, err)
	}
	ip, err := o.res.Lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", host, err)
	}
	target := net.JoinHostPort(ip.String(), port)

	d := &net.Dialer{Timeout: 20 * time.Second, Control: bind.Control(s.WANIndex())}
	if wanIP := s.WANIP(); wanIP != nil {
		if strings.HasPrefix(network, "tcp") {
			d.LocalAddr = &net.TCPAddr{IP: wanIP}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: wanIP}
		}
	}
	return d.DialContext(ctx, network, target)
}

// udpEgress 创建出口侧 UDP socket（绑定 PPPoE 接口）。
func (o *outbound) udpEgress(ctx context.Context) (net.PacketConn, error) {
	s := o.mon.Snapshot()
	if s.WANIndex() == 0 {
		return nil, fmt.Errorf("出站适配器（宽带）未就绪")
	}
	lc := bind.UDPListenConfig(s.WANIndex())
	return lc.ListenPacket(ctx, "udp4", ":0")
}

// serveAll 监听循环：入站适配器 IP 变化或收到退出信号时结束当前监听并重建。
func serveAll(cfg *config.Config, hub *admin.Hub, socksSrv *socks5.Server, httpSrv *httpproxy.Server, mon *netmon.Monitor, restart chan struct{}, quit chan struct{}) {
	for {
		s := mon.Snapshot()
		lip := "0.0.0.0"
		if s.LANIP() != nil {
			lip = s.LANIP().String()
		}

		proxyLn, err := net.Listen("tcp4", net.JoinHostPort(lip, fmt.Sprint(cfg.ListenPort)))
		if err != nil {
			log.Printf("[listen] 监听 %s:%d 失败: %v（5 秒后重试）", lip, cfg.ListenPort, err)
			if !sleepOr(restart, quit, 5*time.Second) {
				return
			}
			continue
		}
		var adminLn net.Listener
		if cfg.AdminPort > 0 {
			adminLn, err = net.Listen("tcp4", net.JoinHostPort(lip, fmt.Sprint(cfg.AdminPort)))
			if err != nil {
				log.Printf("[listen] 状态页监听 %s:%d 失败: %v", lip, cfg.AdminPort, err)
			} else {
				go func(ln net.Listener) {
					if srvErr := http.Serve(ln, hub.Handler()); srvErr != nil && !strings.Contains(srvErr.Error(), "closed") {
						log.Printf("[admin] 状态页服务异常: %v", srvErr)
					}
				}(adminLn)
			}
		}

		log.Printf("代理入口: %s:%d（SOCKS5 + HTTP 混合，UDP=%v）", lip, cfg.ListenPort, cfg.UDP)
		if adminLn != nil {
			log.Printf("状态页: http://%s:%d/    Clash 配置下载: http://%s:%d/clash.yaml", lip, cfg.AdminPort, lip, cfg.AdminPort)
		}

		acceptDone := make(chan struct{})
		go func() {
			mixed.Serve(proxyLn, socksSrv.ServeConn, httpSrv.ServeConn)
			close(acceptDone)
		}()

		select {
		case <-restart:
			log.Println("[listen] 入站适配器变化，重建监听…")
		case <-quit:
			proxyLn.Close()
			if adminLn != nil {
				adminLn.Close()
			}
			return
		}
		proxyLn.Close()
		if adminLn != nil {
			adminLn.Close()
		}
		<-acceptDone
	}
}

func sleepOr(restart chan struct{}, quit chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-restart:
		return true
	case <-quit:
		return false
	case <-t.C:
		return true
	}
}

func writeClashConfig(base string, cfg *config.Config, s netmon.Snapshot) {
	lip := s.LANIP()
	if lip == nil {
		return
	}
	text := clashconf.Generate(lip.String(), cfg.ListenPort, cfg.Auth.Username, cfg.Auth.Password)
	path := filepath.Join(base, "clash-android.yaml")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		log.Printf("[clash] 写入配置失败: %v", err)
		return
	}
	log.Printf("[clash] 已生成手机端配置: %s（代理指向 %s:%d）", path, lip, cfg.ListenPort)
}

func ensureFirewall(cfg *config.Config) {
	var rules []firewall.Rule
	rules = append(rules, firewall.Rule{Name: "LANRelay Proxy TCP", Protocol: "TCP", Port: cfg.ListenPort})
	if cfg.UDP {
		rules = append(rules, firewall.Rule{Name: "LANRelay Proxy UDP", Protocol: "UDP", Port: cfg.ListenPort})
	}
	if cfg.AdminPort > 0 {
		rules = append(rules, firewall.Rule{Name: "LANRelay Admin TCP", Protocol: "TCP", Port: cfg.AdminPort})
	}
	added, manual, err := firewall.Ensure(rules)
	if err != nil {
		log.Printf("[firewall] %v", err)
	}
	if len(added) > 0 {
		log.Printf("[firewall] 已添加放行规则: %s", strings.Join(added, ", "))
	}
	if len(manual) > 0 {
		log.Println("[firewall] 缺少放行规则且当前未以管理员运行，请手动执行：")
		for _, r := range rules {
			for _, name := range manual {
				if name == r.Name {
					log.Printf("    %s", firewall.ManualCommand(r))
				}
			}
		}
	}
}

func printSnapshot(s netmon.Snapshot) {
	if s.LAN != nil {
		log.Printf("入站适配器: %s (ifIndex=%d, IP=%s)", s.LAN.Name, s.LAN.Index, ipStr(s.LANIP()))
	} else {
		log.Printf("入站适配器: 未就绪")
	}
	if s.WAN != nil {
		log.Printf("出站适配器: %s (ifIndex=%d, IP=%s, DNS=%s)", s.WAN.Name, s.WAN.Index, ipStr(s.WANIP()), ipsToStr(s.WAN.DNS))
	} else {
		log.Printf("出站适配器: 未就绪（请确认宽带已拨号）")
	}
}

func setupLog(logFile string) {
	log.SetFlags(log.LstdFlags)
	if logFile == "" {
		return
	}
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("打开日志文件失败: %v（仅输出控制台）", err)
		return
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
}

func cfgIPs(strs []string) []net.IP {
	var out []net.IP
	for _, s := range strs {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func ipsToStr(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return "-"
	}
	return ip.String()
}
