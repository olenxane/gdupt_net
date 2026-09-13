// Package resolver 提供经出站接口（PPPoE）解析域名的 DNS 解析器，带进程内缓存。
package resolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	posCacheTTL = 60 * time.Second
	negCacheTTL = 10 * time.Second
)

type cacheEntry struct {
	ip     net.IP
	expire time.Time
}

// Resolver 出站 DNS 解析器。
type Resolver struct {
	// getServers 动态返回 DNS 服务器 IP 列表（通常来自出站适配器的系统 DNS）
	getServers func() []net.IP
	// control 出站 socket 绑定回调（IP_UNICAST_IF）
	control func(network, address string, c syscall.RawConn) error
	// preferV4 动态返回是否优先使用 IPv4 解析结果
	preferV4 func() bool

	netRes *net.Resolver
	srvIdx atomic.Int64

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// New 创建解析器。
func New(getServers func() []net.IP, control func(network, address string, c syscall.RawConn) error, preferV4 func() bool) *Resolver {
	r := &Resolver{
		getServers: getServers,
		control:    control,
		preferV4:   preferV4,
		cache:      make(map[string]cacheEntry),
	}
	r.netRes = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// 将系统配置的 DNS 服务器改写为我们指定的出站 DNS，且经绑定接口的拨号器发送
			if srv := r.nextServer(); srv != nil {
				address = net.JoinHostPort(srv.String(), "53")
			}
			d := &net.Dialer{Timeout: 5 * time.Second}
			if r.control != nil {
				d.Control = r.control
			}
			return d.DialContext(ctx, network, address)
		},
	}
	return r
}

func (r *Resolver) nextServer() net.IP {
	servers := r.servers()
	if len(servers) == 0 {
		return nil
	}
	i := r.srvIdx.Add(1)
	return servers[int(i-1)%len(servers)]
}

func (r *Resolver) servers() []net.IP {
	if r.getServers != nil {
		if s := r.getServers(); len(s) > 0 {
			return s
		}
	}
	// 兜底公共 DNS
	return []net.IP{net.IPv4(223, 5, 5, 5), net.IPv4(119, 29, 29, 29)}
}

// Lookup 将 host（域名或 IP 字面量）解析为用于连接的 IP。
func (r *Resolver) Lookup(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}

	r.mu.Lock()
	if e, ok := r.cache[host]; ok {
		if time.Now().Before(e.expire) {
			ip := e.ip
			r.mu.Unlock()
			return ip, nil
		}
		delete(r.cache, host)
	}
	r.mu.Unlock()

	addrs, err := r.netRes.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ip := pick(addrs, r.preferV4())
	if ip == nil {
		return nil, &net.DNSError{Err: "no usable address", Name: host, IsNotFound: true}
	}

	r.mu.Lock()
	r.cache[host] = cacheEntry{ip: ip, expire: time.Now().Add(posCacheTTL)}
	r.mu.Unlock()
	return ip, nil
}

// pick 从解析结果中选择 IP：默认优先 IPv4（PPP 出站通常仅 IPv4）。
func pick(addrs []net.IPAddr, preferV4 bool) net.IP {
	var v4, v6 net.IP
	for _, a := range addrs {
		ip := a.IP
		if ip.To4() != nil {
			if v4 == nil {
				v4 = ip
			}
		} else if v6 == nil {
			v6 = ip
		}
	}
	if preferV4 {
		if v4 != nil {
			return v4
		}
		return v6
	}
	if v6 != nil {
		return v6
	}
	return v4
}
