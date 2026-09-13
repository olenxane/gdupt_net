// Package socks5 实现 RFC1928 SOCKS5 服务端（CONNECT 与 UDP ASSOCIATE）。
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	verSocks5 = 5

	cmdConnect      = 1
	cmdBind         = 2
	cmdUDPAssociate = 3

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	authNone     = 0x00
	authUserPass = 0x02
	authReject   = 0xFF

	repOK               = 0
	repGeneralFailure   = 1
	repNotAllowed       = 2 // network unreachable 按规范映射
	repHostUnreachable  = 4
	repConnRefused      = 5
	repTTLExpired       = 6
	repCmdNotSupported  = 7
	repAddrNotSupported = 8
)

var errBadVersion = errors.New("socks5: 协议版本错误")

// Target 解析后的目标地址（Host 为 IP 字面量或域名）。
type Target struct {
	Host string
	Port int
}

func (t Target) String() string {
	return net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
}

// readTarget 从 r 读取 ADDR + PORT（atyp 由调用方从请求头读出）。
func readTarget(r io.Reader, atyp byte) (Target, error) {
	var t Target
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return t, err
		}
		t.Host = net.IP(b[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return t, err
		}
		if l[0] == 0 {
			return t, errors.New("socks5: 域名长度为 0")
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return t, err
		}
		t.Host = string(b)
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return t, err
		}
		t.Host = net.IP(b[:]).String()
	default:
		return t, fmt.Errorf("socks5: 不支持的地址类型 %d", atyp)
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return t, err
	}
	t.Port = int(binary.BigEndian.Uint16(p[:]))
	return t, nil
}

// writeTarget 序列化 ATYP + ADDR + PORT。
func writeTarget(t Target) []byte {
	var out []byte
	if ip := net.ParseIP(t.Host); ip != nil && ip.To4() == nil {
		out = append(out, atypIPv6)
		out = append(out, ip.To16()...)
	} else if ip := net.ParseIP(t.Host); ip != nil {
		out = append(out, atypIPv4)
		out = append(out, ip.To4()...)
	} else {
		out = append(out, atypDomain, byte(len(t.Host)))
		out = append(out, t.Host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(t.Port))
	return append(out, p[:]...)
}

// writeReply 写 SOCKS5 应答，bnd 为 BND.ADDR（nil 表示 0.0.0.0）。
func writeReply(w io.Writer, code byte, bnd net.IP, port int) error {
	out := []byte{verSocks5, code, 0}
	if code != repOK {
		// 失败应答的 BND.ADDR 置 0
		out = append(out, atypIPv4, 0, 0, 0, 0, 0, 0)
		_, err := w.Write(out)
		return err
	}
	out = append(out, writeTarget(Target{Host: hostOf(bnd), Port: port})...)
	_, err := w.Write(out)
	return err
}

func hostOf(ip net.IP) string {
	if ip == nil {
		return "0.0.0.0"
	}
	if ip.To4() == nil {
		return ip.String()
	}
	if ip.IsUnspecified() {
		return "0.0.0.0"
	}
	return ip.To4().String()
}

// dialErrToRep 将拨号错误映射为 SOCKS5 应答码。
func dialErrToRep(err error) byte {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case windows.WSAECONNREFUSED:
			return repConnRefused
		case windows.WSAETIMEDOUT:
			return repTTLExpired
		case windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH, windows.WSAECONNRESET:
			return repHostUnreachable
		}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return repHostUnreachable
	}
	return repGeneralFailure
}
