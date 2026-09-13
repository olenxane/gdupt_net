package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"lanrelay/internal/relay"
	"lanrelay/internal/stats"
)

const (
	handshakeTimeout = 15 * time.Second
	dialTimeout      = 20 * time.Second
	udpIdleTimeout   = 120 * time.Second
)

// Server SOCKS5 服务端。
type Server struct {
	// Dial 出站拨号（绑定 PPPoE 接口、内置域名解析）
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Resolve 域名解析（绑定 PPPoE 出站 DNS），UDP 中转使用
	Resolve func(ctx context.Context, host string) (net.IP, error)
	// UDPEnabled 是否允许 UDP ASSOCIATE
	UDPEnabled bool
	// NewEgress 创建出口侧 UDP socket（绑定 PPPoE 接口）
	NewEgress func(ctx context.Context) (net.PacketConn, error)
	// QUICBlock 丢弃目标为 UDP 443 的数据包
	QUICBlock bool
	// 认证（两者均非空时启用 RFC1929 用户名密码）
	AuthUser, AuthPass string
}

// ServeConn 处理一条已嗅探为 SOCKS5 的连接。
func (s *Server) ServeConn(c net.Conn, br *bufio.Reader) {
	defer c.Close()
	stats.TCPActive.Add(1)
	defer stats.TCPActive.Add(-1)

	c.SetDeadline(time.Now().Add(handshakeTimeout))
	method, err := s.greeting(c, br)
	if err != nil {
		log.Printf("[socks5] %s 握手失败: %v", c.RemoteAddr(), err)
		return
	}
	if method == authUserPass {
		if err := s.authUserPass(c, br); err != nil {
			log.Printf("[socks5] %s 认证失败: %v", c.RemoteAddr(), err)
			return
		}
	}

	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil { // VER CMD RSV ATYP
		log.Printf("[socks5] %s 读取请求头失败: %v", c.RemoteAddr(), err)
		return
	}
	if hdr[0] != verSocks5 {
		log.Printf("[socks5] %s 请求版本错误: %d", c.RemoteAddr(), hdr[0])
		return
	}
	tgt, err := readTarget(br, hdr[3])
	if err != nil {
		log.Printf("[socks5] %s 读取目标地址失败: %v", c.RemoteAddr(), err)
		_ = writeReply(c, repGeneralFailure, nil, 0)
		return
	}

	switch hdr[1] {
	case cmdConnect:
		s.handleConnect(c, tgt)
	case cmdUDPAssociate:
		s.handleUDPAssociate(c, br, tgt)
	case cmdBind:
		_ = writeReply(c, repCmdNotSupported, nil, 0)
	default:
		_ = writeReply(c, repCmdNotSupported, nil, 0)
	}
}

// greeting 处理方法协商，返回选定的方法。
func (s *Server) greeting(c net.Conn, br *bufio.Reader) (byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return 0, err
	}
	if head[0] != verSocks5 {
		return 0, fmt.Errorf("协议版本 %d 非 SOCKS5", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return 0, err
	}
	wantAuth := s.AuthUser != "" || s.AuthPass != ""
	if wantAuth {
		for _, m := range methods {
			if m == authUserPass {
				if _, err := c.Write([]byte{verSocks5, authUserPass}); err != nil {
					return 0, err
				}
				return authUserPass, nil
			}
		}
		_, _ = c.Write([]byte{verSocks5, authReject})
		return 0, errors.New("客户端不支持用户名密码认证")
	}
	for _, m := range methods {
		if m == authNone {
			_, err := c.Write([]byte{verSocks5, authNone})
			return authNone, err
		}
	}
	_, _ = c.Write([]byte{verSocks5, authReject})
	return 0, errors.New("客户端无可用认证方法")
}

// authUserPass 处理 RFC1929 用户名密码子协商。
func (s *Server) authUserPass(c net.Conn, br *bufio.Reader) error {
	var ver [1]byte
	if _, err := io.ReadFull(br, ver[:]); err != nil {
		return err
	}
	if ver[0] != 1 {
		return fmt.Errorf("子协商版本 %d", ver[0])
	}
	u, err := readShortString(br)
	if err != nil {
		return err
	}
	p, err := readShortString(br)
	if err != nil {
		return err
	}
	if u != s.AuthUser || p != s.AuthPass {
		_, _ = c.Write([]byte{1, 1})
		return errors.New("用户名或密码错误")
	}
	_, err = c.Write([]byte{1, 0})
	return err
}

func readShortString(r io.Reader) (string, error) {
	var l [1]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", err
	}
	b := make([]byte, l[0])
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// handleConnect 处理 TCP CONNECT。
func (s *Server) handleConnect(c net.Conn, tgt Target) {
	stats.ConnsTotal.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	remote, err := s.Dial(ctx, "tcp", tgt.String())
	if err != nil {
		rep := dialErrToRep(err)
		log.Printf("[socks5] CONNECT %s 失败: %v", tgt, err)
		_ = writeReply(c, rep, nil, 0)
		return
	}
	defer remote.Close()

	bnd := "0.0.0.0"
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok && la.IP != nil && !la.IP.IsUnspecified() {
		bnd = la.IP.String()
	}
	if err := writeReply(c, repOK, net.ParseIP(bnd), 0); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	log.Printf("[socks5] CONNECT %s 已建立（来自 %s）", tgt, c.RemoteAddr())
	relay.Pipe(c, remote)
}

// handleUDPAssociate 处理 UDP ASSOCIATE。
func (s *Server) handleUDPAssociate(c net.Conn, br *bufio.Reader, tgt Target) {
	if !s.UDPEnabled || s.NewEgress == nil {
		_ = writeReply(c, repCmdNotSupported, nil, 0)
		return
	}

	// 客户端侧 UDP socket：绑定在与客户端通信的本地地址上
	lip := "0.0.0.0:0"
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok && la.IP != nil && !la.IP.IsUnspecified() {
		lip = net.JoinHostPort(la.IP.String(), "0")
	}
	clientPC, err := net.ListenPacket("udp4", lip)
	if err != nil {
		log.Printf("[socks5] UDP ASSOCIATE 创建客户端 socket 失败: %v", err)
		_ = writeReply(c, repGeneralFailure, nil, 0)
		return
	}
	defer clientPC.Close()

	egress, err := s.NewEgress(context.Background())
	if err != nil {
		log.Printf("[socks5] UDP ASSOCIATE 创建出口 socket 失败: %v", err)
		_ = writeReply(c, repGeneralFailure, nil, 0)
		return
	}
	defer egress.Close()

	clientPort := clientPC.LocalAddr().(*net.UDPAddr).Port
	bnd := "0.0.0.0"
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok && la.IP != nil && !la.IP.IsUnspecified() {
		bnd = la.IP.String()
	}
	if err := writeReply(c, repOK, net.ParseIP(bnd), clientPort); err != nil {
		return
	}
	log.Printf("[socks5] UDP ASSOCIATE 中转端口 %d（来自 %s）", clientPort, c.RemoteAddr())

	stats.UDPActive.Add(1)
	defer stats.UDPActive.Add(-1)

	a := &udpAssoc{
		client: clientPC,
		egress: egress,
		srv:    s,
	}
	a.run(c, br)
}

// udpAssoc 单个 UDP 中转会话。
type udpAssoc struct {
	client     net.PacketConn
	egress     net.PacketConn
	srv        *Server
	clientAddr atomic.Pointer[net.UDPAddr]
	targets    sync.Map // netip.AddrPort -> struct{}（允许回包的远端）
	lastActive atomic.Int64
	closeOnce  sync.Once
	closed     chan struct{}
}

func (a *udpAssoc) touch() { a.lastActive.Store(time.Now().Unix()) }

func (a *udpAssoc) run(control net.Conn, br *bufio.Reader) {
	a.closed = make(chan struct{})
	a.touch()

	// TCP 控制连接关闭 → 结束 UDP 会话（RFC1928）
	go func() {
		_, _ = io.Copy(io.Discard, br)
		a.closeOnce.Do(func() { close(a.closed) })
		a.client.Close()
		a.egress.Close()
	}()

	// 空闲超时看门狗
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-a.closed:
				return
			case <-t.C:
				if time.Since(time.Unix(a.lastActive.Load(), 0)) > udpIdleTimeout {
					log.Printf("[socks5] UDP 会话空闲超时（%s）", a.clientAddr.Load())
					a.closeOnce.Do(func() { close(a.closed) })
					a.client.Close()
					a.egress.Close()
					return
				}
			}
		}
	}()

	done := make(chan struct{}, 2)
	go a.clientToEgress(done)
	go a.egressToClient(done)
	<-done
	<-done
	a.closeOnce.Do(func() { close(a.closed) })
	control.SetDeadline(time.Now()) // 促使控制连接读取协程退出
}

// clientToEgress 客户端 → 互联网 方向。
func (a *udpAssoc) clientToEgress(done chan struct{}) {
	defer func() { done <- struct{}{} }()
	buf := make([]byte, 65535)
	for {
		n, from, err := a.client.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case <-a.closed:
			return
		default:
		}
		a.touch()

		fromAddr := from.(*net.UDPAddr)
		if cur := a.clientAddr.Load(); cur == nil {
			a.clientAddr.Store(fromAddr)
		} else if !udpAddrEqual(cur, fromAddr) {
			continue // 仅接受发起会话的客户端地址
		}
		if n < 4 {
			continue
		}
		payload, tgt, err := unwrapUDP(buf[:n])
		if err != nil {
			continue
		}
		if a.srv.QUICBlock && tgt.Port == 443 {
			continue
		}
		// IP 字面量直接使用，域名才需要解析
		ip := net.ParseIP(tgt.Host)
		if ip == nil {
			ip, err = a.srv.Resolve(context.Background(), tgt.Host)
			if err != nil {
				log.Printf("[socks5] UDP 目标解析失败 %s: %v", tgt, err)
				continue
			}
		}
		if ip.To4() == nil {
			continue // 出口 socket 为 udp4
		}
		dst := &net.UDPAddr{IP: ip, Port: tgt.Port}
		ap, ok := udpAddrPort(dst)
		if !ok {
			continue
		}
		a.targets.Store(ap, struct{}{})
		if _, err := a.egress.WriteTo(payload, dst); err != nil {
			return
		}
		stats.BytesUp.Add(int64(len(payload)))
	}
}

// egressToClient 互联网 → 客户端 方向。
func (a *udpAssoc) egressToClient(done chan struct{}) {
	defer func() { done <- struct{}{} }()
	buf := make([]byte, 65535)
	for {
		n, from, err := a.egress.ReadFrom(buf)
		if err != nil {
			return
		}
		select {
		case <-a.closed:
			return
		default:
		}
		a.touch()

		fromAddr, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap, ok := udpAddrPort(fromAddr)
		if !ok {
			continue
		}
		if _, allowed := a.targets.Load(ap); !allowed {
			continue // 仅转发我们请求过的远端
		}
		client := a.clientAddr.Load()
		if client == nil {
			continue
		}
		wrapped := wrapUDP(Target{Host: fromAddr.IP.String(), Port: fromAddr.Port}, buf[:n])
		if _, err := a.client.WriteTo(wrapped, client); err != nil {
			return
		}
		stats.BytesDown.Add(int64(n))
	}
}

// unwrapUDP 拆包：RSV(2) FRAG(1) ATYP(1) ADDR PORT PAYLOAD。
func unwrapUDP(b []byte) (payload []byte, tgt Target, err error) {
	if len(b) < 4 {
		return nil, tgt, errors.New("UDP 包过短")
	}
	if b[2] != 0 { // FRAG 非 0：不支持分片
		return nil, tgt, errors.New("不支持 UDP 分片")
	}
	atyp := b[3]
	tgt, err = readTarget(newByteReader(b[4:]), atyp)
	if err != nil {
		return nil, tgt, err
	}
	// 计算 payload 起点：RSV(2)+FRAG(1)+ATYP(1) + 地址 + PORT(2)
	off := 4
	switch atyp {
	case atypIPv4:
		off += 4
	case atypIPv6:
		off += 16
	case atypDomain:
		if len(b) < 5 {
			return nil, tgt, errors.New("UDP 包过短")
		}
		off += 1 + int(b[4])
	default:
		return nil, tgt, errors.New("UDP 地址类型错误")
	}
	off += 2 // PORT
	if off > len(b) {
		return nil, tgt, errors.New("UDP 包过短")
	}
	return b[off:], tgt, nil
}

// wrapUDP 打包回程：RSV(2)=0 FRAG(1)=0 ATYP ADDR PORT PAYLOAD。
func wrapUDP(tgt Target, payload []byte) []byte {
	out := []byte{0, 0, 0}
	out = append(out, writeTarget(tgt)...)
	return append(out, payload...)
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

func udpAddrPort(a *net.UDPAddr) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), true
}

type byteReader struct {
	b []byte
	i int
}

func newByteReader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// ReadByte 满足 io.ByteReader。
func (r *byteReader) ReadByte() (byte, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	c := r.b[r.i]
	r.i++
	return c, nil
}
