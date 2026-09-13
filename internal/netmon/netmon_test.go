package netmon

import (
	"net"
	"testing"
)

func mkAdapters() []Adapter {
	return []Adapter{
		{Name: "以太网", Index: 2, IfType: 6, Up: true, V4: []net.IP{net.IPv4(169, 254, 115, 24)}},
		{Name: "WLAN", Index: 12, IfType: 71, Up: true, V4: []net.IP{net.IPv4(192, 168, 25, 177)}, DNS: []net.IP{net.IPv4(192, 168, 25, 39)}},
		{Name: "校园网", Index: 70, IfType: ifTypePPP, Up: true, V4: []net.IP{net.IPv4(10, 200, 126, 18)}, DNS: []net.IP{net.IPv4(114, 114, 114, 114)}},
		{Name: "uu", Index: 22, IfType: 6, Up: false},
		{Name: "本地连接* 9", Index: 5, IfType: 71, Up: false},
	}
}

func TestPickLANAuto(t *testing.T) {
	lan, err := pickLAN(mkAdapters(), "auto")
	if err != nil {
		t.Fatalf("pickLAN: %v", err)
	}
	if lan.Name != "WLAN" {
		t.Fatalf("期望选择 WLAN，实际 %s", lan.Name)
	}
	if !lan.FirstV4().Equal(net.IPv4(192, 168, 25, 177)) {
		t.Fatalf("WLAN IP 错误: %s", lan.FirstV4())
	}
}

func TestPickLANExplicit(t *testing.T) {
	lan, err := pickLAN(mkAdapters(), "以太网")
	if err == nil {
		t.Fatalf("以太网只有 APIPA 地址，应报错，实际选了 %s", lan.Name)
	}
	lan, err = pickLAN(mkAdapters(), "WLAN")
	if err != nil || lan.Name != "WLAN" {
		t.Fatalf("显式指定 WLAN 失败: %v", err)
	}
	lan, err = pickLAN(mkAdapters(), "12")
	if err != nil || lan.Name != "WLAN" {
		t.Fatalf("按 ifIndex 指定失败: %v", err)
	}
	lan, err = pickLAN(mkAdapters(), "192.168.25.177")
	if err != nil || lan.Name != "WLAN" {
		t.Fatalf("按 IP 指定失败: %v", err)
	}
}

func TestPickWANAutoPrefersPPP(t *testing.T) {
	lan, _ := pickLAN(mkAdapters(), "auto")
	wan, err := pickWAN(mkAdapters(), "auto", lan)
	if err != nil {
		t.Fatalf("pickWAN: %v", err)
	}
	if wan.Name != "校园网" || wan.IfType != ifTypePPP {
		t.Fatalf("期望选择 PPP 适配器「校园网」，实际 %s", wan.Name)
	}
	if !wan.FirstV4().Equal(net.IPv4(10, 200, 126, 18)) {
		t.Fatalf("WAN IP 错误: %s", wan.FirstV4())
	}
}

func TestPickWANExplicitName(t *testing.T) {
	lan, _ := pickLAN(mkAdapters(), "auto")
	wan, err := pickWAN(mkAdapters(), "校园网", lan)
	if err != nil || wan.Index != 70 {
		t.Fatalf("显式指定校园网失败: %v", err)
	}
}

func TestPickWANExcludesLAN(t *testing.T) {
	ads := []Adapter{
		{Name: "以太网", Index: 2, IfType: 6, Up: true, V4: []net.IP{net.IPv4(192, 168, 1, 10)}},
		{Name: "WLAN", Index: 12, IfType: 71, Up: true, V4: []net.IP{net.IPv4(192, 168, 25, 177)}},
	}
	lan, _ := pickLAN(ads, "auto")
	if lan.Name != "WLAN" {
		t.Fatalf("LAN 应为 WLAN，实际 %s", lan.Name)
	}
	// 唯一候选（排除 LAN 后只剩以太网）自动选用
	wan, err := pickWAN(ads, "auto", lan)
	if err != nil || wan.Name != "以太网" {
		t.Fatalf("唯一候选应自动选用: %v %s", err, wan.Name)
	}
}

func TestPickWANAmbiguous(t *testing.T) {
	ads := []Adapter{
		{Name: "以太网", Index: 2, IfType: 6, Up: true, V4: []net.IP{net.IPv4(192, 168, 1, 10)}},
		{Name: "以太网 2", Index: 3, IfType: 6, Up: true, V4: []net.IP{net.IPv4(192, 168, 2, 10)}},
		{Name: "WLAN", Index: 12, IfType: 71, Up: true, V4: []net.IP{net.IPv4(192, 168, 25, 177)}},
	}
	lan, _ := pickLAN(ads, "auto")
	if _, err := pickWAN(ads, "auto", lan); err == nil {
		t.Fatalf("多个候选时应报错")
	}
}

func TestPickWANNoPPPWithDNSFallback(t *testing.T) {
	ads := []Adapter{
		{Name: "WLAN", Index: 12, IfType: 71, Up: true, V4: []net.IP{net.IPv4(192, 168, 25, 177)}},
		{Name: "以太网", Index: 2, IfType: 6, Up: true, V4: []net.IP{net.IPv4(10, 0, 0, 5)}, DNS: []net.IP{net.IPv4(8, 8, 8, 8)}},
	}
	lan, _ := pickLAN(ads, "auto")
	wan, err := pickWAN(ads, "auto", lan)
	if err != nil || wan.Name != "以太网" {
		t.Fatalf("无 PPP 时应回落选带 DNS 的适配器: %v %s", err, adapterName(wan))
	}
}

func adapterName(a *Adapter) string {
	if a == nil {
		return ""
	}
	return a.Name
}
