//go:build windows

// Package bind 将 socket 的出站流量强制绑定到指定网络适配器（接口）。
//
// 核心手段是 Windows 的 IP_UNICAST_IF(31) / IPV6_UNICAST_IF(31) socket 选项，
// 它直接决定单播发送所走的接口与源地址选择，不受路由表 metric 变化影响；
// 同时支持以接口 IP 作为 LocalAddr 双保险（Windows 强主机模型下同样强制出接口）。
package bind

import (
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF（ws2ipdef.h）
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
)

// softFailOnce IP_UNICAST_IF 设置失败时降级为仅 LocalAddr 绑定，只告警一次。
var softFailOnce atomic.Bool

// Control 返回用于 net.Dialer.Control / net.ListenConfig.Control 的回调，
// 将 socket 出口绑定到 ifIndex 指定的接口。
func Control(ifIndex int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		opErr := c.Control(func(fd uintptr) {
			sockErr = apply(fd, address, ifIndex)
		})
		if opErr != nil {
			return opErr
		}
		if sockErr != nil && softFailOnce.CompareAndSwap(false, true) {
			log.Printf("[bind] 设置 IP_UNICAST_IF 失败（%v），降级为仅 LocalAddr 绑定出站接口", sockErr)
		}
		if sockErr != nil {
			return nil // 软失败：交由 LocalAddr / 路由表兜底
		}
		return nil
	}
}

// apply 对 socket 设置按目标地址族区分的接口绑定选项。
func apply(fd uintptr, address string, ifIndex int) error {
	v4 := true
	if ip, err := parseIP(address); err == nil {
		if ip.Is6() && !ip.Is4In6() {
			v4 = false
		}
	}
	if v4 {
		return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, htonl(ifIndex))
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, ipv6UnicastIf, ifIndex)
}

func parseIP(address string) (netip.Addr, error) {
	if ap, err := netip.ParseAddrPort(address); err == nil {
		return ap.Addr(), nil
	}
	return netip.ParseAddr(address)
}

// htonl IPv4 的 IP_UNICAST_IF 要求接口索引为网络字节序。
func htonl(v int) int {
	u := uint32(v)
	return int((u&0xff)<<24 | (u&0xff00)<<8 | (u>>8)&0xff00 | (u>>24)&0xff)
}

// Dialer 返回绑定到出站接口的 TCP/UDP 拨号器。
// localIP 为出站接口当前 IP（可为 nil，仅用 IP_UNICAST_IF）；network 为 "tcp"/"tcp4"/"udp" 等。
func Dialer(ifIndex int, localIP net.IP, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, Control: Control(ifIndex)}
	if localIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	return d
}

// UDPListenConfig 返回绑定到出站接口的 UDP 监听配置（用于出口侧 UDP 中转 socket）。
func UDPListenConfig(ifIndex int) *net.ListenConfig {
	return &net.ListenConfig{Control: Control(ifIndex)}
}
