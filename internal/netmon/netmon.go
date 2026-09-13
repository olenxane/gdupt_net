// Package netmon 负责发现并监控网络适配器：
// 入站侧（WLAN 等局域网适配器，用于监听代理端口）与
// 出站侧（PPPoE 拨号的 PPP 适配器，用于强制绑定出口）。
// 适配器选择逻辑为平台无关的纯函数，平台相关枚举见 fetch_windows.go。
package netmon

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ifTypePPP 与 Windows 平台枚举保持一致（在 fetch_windows.go 中亦有定义，用于文档）。
// PPPoE 宽带拨号成功后体现为 IfType==23 的 PPP 适配器。
const ifTypePPP = 23

// Adapter 平台无关的适配器描述。
type Adapter struct {
	Name   string
	Index  int
	IfType uint32
	Up     bool
	V4     []net.IP
	HasV6  bool
	DNS    []net.IP
}

// FirstV4 返回适配器首选 IPv4。
func (a *Adapter) FirstV4() net.IP {
	return firstV4(a.V4)
}

// Snapshot 一次适配器状态快照。
type Snapshot struct {
	LAN *Adapter // 入站（监听）适配器
	WAN *Adapter // 出站（PPPoE）适配器
}

// Ready 入站与出站适配器是否均已就绪。
func (s Snapshot) Ready() bool {
	return s.LAN != nil && s.WAN != nil
}

// LANIP 入站适配器首选 IPv4。
func (s Snapshot) LANIP() net.IP {
	if s.LAN == nil {
		return nil
	}
	return s.LAN.FirstV4()
}

// WANIP 出站适配器首选 IPv4。
func (s Snapshot) WANIP() net.IP {
	if s.WAN == nil {
		return nil
	}
	return s.WAN.FirstV4()
}

// WANIndex 出站适配器 ifIndex（绑定出口用）。
func (s Snapshot) WANIndex() int {
	if s.WAN == nil {
		return 0
	}
	return s.WAN.Index
}

// DNSServers 出站适配器可用的 DNS 服务器。
func (s Snapshot) DNSServers() []net.IP {
	if s.WAN == nil || len(s.WAN.DNS) == 0 {
		return nil
	}
	return s.WAN.DNS
}

func firstV4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil && !ip.IsUnspecified() {
			return ip
		}
	}
	return nil
}

var (
	reWiFiName = regexp.MustCompile(`(?i)wlan|wi-?fi|无线`)
	reExclude  = regexp.MustCompile(`(?i)loopback|virtual|vethernet|vmware|virtualbox|hyper-v|wsl|npcap|wi-fi direct|direct-|bluetooth|蓝牙|tap|tun|vpn|本地连接`)
)

// usableV4 返回适配器上首个「可用于对外通信」的 IPv4：
// 排除回环、未指定地址与 APIPA 自检地址（169.254/16）。
func usableV4(a Adapter) net.IP {
	for _, ip := range a.V4 {
		b := ip.To4()
		if b == nil || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		if b[0] == 169 && b[1] == 254 { // APIPA 自检地址，链路未真正可用
			continue
		}
		return ip
	}
	return nil
}

// routablePrivate 返回适配器上首个 RFC1918 私网 IPv4。
func routablePrivate(a Adapter) net.IP {
	ip := usableV4(a)
	if ip == nil {
		return nil
	}
	b := ip.To4()
	if b[0] == 192 && b[1] == 168 ||
		b[0] == 10 ||
		(b[0] == 172 && b[1] >= 16 && b[1] <= 31) {
		return ip
	}
	return nil
}

// findByCfg 按配置串查找适配器：整数→ifIndex，IP→包含该地址，其余→适配器名（忽略大小写，支持包含匹配）。
func findByCfg(ads []Adapter, cfg string) *Adapter {
	cfg = strings.TrimSpace(cfg)
	if cfg == "" || strings.EqualFold(cfg, "auto") {
		return nil
	}
	for i := range ads {
		if fmt.Sprint(ads[i].Index) == cfg {
			return &ads[i]
		}
	}
	if ip := net.ParseIP(cfg); ip != nil {
		for i := range ads {
			for _, a := range ads[i].V4 {
				if a.Equal(ip) {
					return &ads[i]
				}
			}
			if ip.To4() == nil && ads[i].HasV6 {
				return &ads[i]
			}
		}
	}
	for i := range ads {
		if strings.EqualFold(ads[i].Name, cfg) {
			return &ads[i]
		}
	}
	for i := range ads {
		if strings.Contains(ads[i].Name, cfg) {
			return &ads[i]
		}
	}
	return nil
}

// pickLAN 选择入站（监听）适配器。
// 规则：显式配置优先；auto 时在「已连接、有 RFC1918 私网 IPv4、非 PPP、非虚拟」中
// 优先选 WLAN 类无线网卡，其次 ifIndex 最小者。
func pickLAN(ads []Adapter, cfg string) (*Adapter, error) {
	if a := findByCfg(ads, cfg); a != nil {
		if !a.Up {
			return nil, fmt.Errorf("入站适配器 %q 未连接", a.Name)
		}
		if usableV4(*a) == nil {
			return nil, fmt.Errorf("入站适配器 %q 无可用的 IPv4 地址", a.Name)
		}
		return a, nil
	}
	var cands []Adapter
	for _, a := range ads {
		if !a.Up || a.IfType == ifTypePPP {
			continue
		}
		if routablePrivate(a) == nil {
			continue
		}
		if reExclude.MatchString(a.Name) {
			continue
		}
		cands = append(cands, a)
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("未发现可用的局域网适配器（无线网卡需已连入局域网并取得私网 IPv4）")
	}
	sort.Slice(cands, func(i, j int) bool {
		wi, wj := reWiFiName.MatchString(cands[i].Name), reWiFiName.MatchString(cands[j].Name)
		if wi != wj {
			return wi
		}
		return cands[i].Index < cands[j].Index
	})
	return &cands[0], nil
}

// pickWAN 选择出站适配器（PPPoE 拨号出口）。
// 规则：显式配置优先；auto 时在「已连接、有 IPv4、非入站适配器」中
// 优先选 PPP 类型（宽带拨号），其次携带 DNS 服务器者，最后要求候选唯一。
func pickWAN(ads []Adapter, cfg string, lan *Adapter) (*Adapter, error) {
	if a := findByCfg(ads, cfg); a != nil {
		if !a.Up {
			return nil, fmt.Errorf("出站适配器 %q 未连接", a.Name)
		}
		if usableV4(*a) == nil {
			return nil, fmt.Errorf("出站适配器 %q 无可用的 IPv4 地址（宽带可能未拨通）", a.Name)
		}
		return a, nil
	}
	var ppp, withDNS, all []Adapter
	for _, a := range ads {
		if !a.Up || usableV4(a) == nil {
			continue
		}
		if firstV4(a.V4).IsLoopback() {
			continue
		}
		if lan != nil && a.Index == lan.Index {
			continue
		}
		all = append(all, a)
		if a.IfType == ifTypePPP {
			ppp = append(ppp, a)
		}
		if len(a.DNS) > 0 {
			withDNS = append(withDNS, a)
		}
	}
	switch {
	case len(ppp) > 0:
		sort.Slice(ppp, func(i, j int) bool { return ppp[i].Index < ppp[j].Index })
		return &ppp[0], nil
	case len(all) == 1:
		return &all[0], nil
	case len(withDNS) > 0:
		sort.Slice(withDNS, func(i, j int) bool { return withDNS[i].Index < withDNS[j].Index })
		return &withDNS[0], nil
	case len(all) > 1:
		names := make([]string, 0, len(all))
		for _, a := range all {
			names = append(names, fmt.Sprintf("%s(ifIndex=%d)", a.Name, a.Index))
		}
		return nil, fmt.Errorf("存在多个候选出口适配器，请在配置 wan: 中指定其一：%s", strings.Join(names, ", "))
	default:
		return nil, fmt.Errorf("未发现可用的出站适配器（请先完成宽带 PPPoE 拨号）")
	}
}

// Monitor 周期轮询适配器状态并维护最新快照。
type Monitor struct {
	cfgListen string
	cfgWAN    string
	interval  time.Duration
	fetch     func() ([]Adapter, error)

	snap    atomic.Pointer[Snapshot]
	mu      sync.Mutex
	cbs     []func(old, new Snapshot)
	stopped chan struct{}
	once    sync.Once
}

// New 创建监控器；fetch 传入适配器枚举实现（生产环境为 fetchAdapters）。
func New(cfgListen, cfgWAN string, interval time.Duration, fetch func() ([]Adapter, error)) *Monitor {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	m := &Monitor{
		cfgListen: cfgListen,
		cfgWAN:    cfgWAN,
		interval:  interval,
		fetch:     fetch,
		stopped:   make(chan struct{}),
	}
	m.snap.Store(&Snapshot{})
	return m
}

// OnChange 注册快照变化回调（适配器切换、IP 变化时触发）。
func (m *Monitor) OnChange(cb func(old, new Snapshot)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cbs = append(m.cbs, cb)
}

// Snapshot 返回当前快照。
func (m *Monitor) Snapshot() Snapshot {
	return *m.snap.Load()
}

// WaitReady 阻塞等待入站与出站适配器均就绪。
func (m *Monitor) WaitReady(timeout time.Duration) error {
	deadline := time.After(timeout)
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		if m.Snapshot().Ready() {
			return nil
		}
		select {
		case <-deadline:
			return fmt.Errorf("等待适配器就绪超时（%s）", timeout)
		case <-t.C:
		}
	}
}

// Run 启动轮询，直到 Stop 被调用。
func (m *Monitor) Run() {
	m.refresh()
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.stopped:
			return
		case <-t.C:
			m.refresh()
		}
	}
}

// Stop 停止轮询。
func (m *Monitor) Stop() {
	m.once.Do(func() { close(m.stopped) })
}

func (m *Monitor) refresh() {
	ads, err := m.fetch()
	if err != nil {
		log.Printf("[netmon] 枚举适配器失败: %v", err)
		return
	}
	old := m.Snapshot()
	var ns Snapshot
	ns.LAN, err = pickLAN(ads, m.cfgListen)
	if err != nil {
		log.Printf("[netmon] 入站适配器未就绪: %v", err)
	}
	wan, werr := pickWAN(ads, m.cfgWAN, ns.LAN)
	if werr != nil {
		log.Printf("[netmon] 出站适配器未就绪: %v", werr)
	}
	ns.WAN = wan
	m.snap.Store(&ns)

	if changed(old, ns) {
		log.Printf("[netmon] 适配器状态变化: 入站=%s 出站=%s(ifIndex=%d, IP=%s)",
			describe(ns.LAN), describe(ns.WAN), ns.WANIndex(), ipStr(ns.WANIP()))
		m.mu.Lock()
		cbs := append([]func(old, new Snapshot){}, m.cbs...)
		m.mu.Unlock()
		for _, cb := range cbs {
			cb(old, ns)
		}
	}
}

func changed(a, b Snapshot) bool {
	return ipStr(a.LANIP()) != ipStr(b.LANIP()) || lanName(a) != lanName(b) ||
		a.WANIndex() != b.WANIndex() || ipStr(a.WANIP()) != ipStr(b.WANIP())
}

func lanName(s Snapshot) string {
	if s.LAN == nil {
		return ""
	}
	return s.LAN.Name
}

func describe(a *Adapter) string {
	if a == nil {
		return "未就绪"
	}
	return fmt.Sprintf("%s(ifIndex=%d, IP=%s)", a.Name, a.Index, ipStr(a.FirstV4()))
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return "-"
	}
	return ip.String()
}
