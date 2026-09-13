//go:build windows

// Windows 平台适配器枚举：基于 GetAdaptersAddresses。
package netmon

import (
	"errors"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const ifTypePPPW = 23 // IF_TYPE_PPP：宽带拨号（PPPoE）适配器

// FetchAdapters 枚举本机所有适配器（含未连接的）。
func FetchAdapters() ([]Adapter, error) {
	const family = uint32(windows.AF_UNSPEC)
	flags := uint32(windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST)

	var size uint32
	if err := windows.GetAdaptersAddresses(family, flags, 0, nil, &size); err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, err
	}
	if size == 0 {
		return nil, errors.New("GetAdaptersAddresses 返回缓冲区大小为 0")
	}
	buf := make([]byte, size)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(family, flags, 0, aa, &size); err != nil {
		return nil, err
	}

	var out []Adapter
	for ; aa != nil; aa = aa.Next {
		a := Adapter{
			Name:   windows.UTF16PtrToString(aa.FriendlyName),
			Index:  int(aa.IfIndex),
			IfType: aa.IfType,
			Up:     aa.OperStatus == windows.IfOperStatusUp,
		}
		if a.IfType == ifTypePPPW {
			a.IfType = ifTypePPP // 与纯逻辑侧常量保持一致
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip := sockaddrIP(ua.Address)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				a.V4 = append(a.V4, ip)
			} else {
				a.HasV6 = true
			}
		}
		for da := aa.FirstDnsServerAddress; da != nil; da = da.Next {
			if ip := sockaddrIP(da.Address); ip != nil {
				a.DNS = append(a.DNS, ip)
			}
		}
		out = append(out, a)
	}
	return out, nil
}

func sockaddrIP(sa windows.SocketAddress) net.IP {
	if sa.Sockaddr == nil {
		return nil
	}
	switch sa.Sockaddr.Addr.Family {
	case syscall.AF_INET:
		a := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa.Sockaddr))
		return append(net.IP{}, a.Addr[:]...)
	case syscall.AF_INET6:
		a := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sa.Sockaddr))
		return append(net.IP{}, a.Addr[:]...)
	}
	return nil
}
