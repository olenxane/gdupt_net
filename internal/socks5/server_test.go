package socks5

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// fakeDial 将拨号接到本地回声服务，模拟出站连接。
func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func dialHandshake(t *testing.T, srvAddr, dstHost string, dstPort int, methods []byte) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp4", srvAddr)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	_, _ = c.Write(append([]byte{5, byte(len(methods))}, methods...))
	br := bufio.NewReader(c)
	var resp [2]byte
	if _, err := io.ReadFull(br, resp[:]); err != nil {
		t.Fatalf("读方法协商应答: %v", err)
	}
	if resp[0] != 5 || resp[1] != authNone {
		t.Fatalf("方法协商应答异常: %v", resp)
	}
	// CONNECT 请求
	req := []byte{5, cmdConnect, 0}
	req = append(req, writeTarget(Target{Host: dstHost, Port: dstPort})...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("发送 CONNECT: %v", err)
	}
	var rep [4]byte
	if _, err := io.ReadFull(br, rep[:]); err != nil {
		t.Fatalf("读 CONNECT 应答: %v", err)
	}
	if rep[1] != repOK {
		t.Fatalf("CONNECT 应答码 = %d", rep[1])
	}
	// 读完 BND
	bndTgt, err := readTarget(br, rep[3])
	if err != nil {
		t.Fatalf("读 BND: %v", err)
	}
	_ = bndTgt
	return c, br
}

func TestServeConnConnectEcho(t *testing.T) {
	echo := startEcho(t)
	srv := &Server{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, echo.Addr().String())
	}}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go ServeLoop(ln, srv)

	c, br := dialHandshake(t, ln.Addr().String(), "test.example.com", 80, []byte{authNone})
	defer c.Close()
	msg := []byte("hello through relay")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("写数据: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("读回声: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("回声不一致: %q", got)
	}
}

func TestServeConnAuthReject(t *testing.T) {
	srv := &Server{AuthUser: "u", AuthPass: "p"}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go ServeLoop(ln, srv)

	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{5, 1, authNone})
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatalf("读应答: %v", err)
	}
	if resp[1] != authReject {
		t.Fatalf("无凭据客户端应被拒绝，实际 %d", resp[1])
	}
}

func TestUDPAssociateRelay(t *testing.T) {
	// 本地 UDP 回声模拟远端服务
	udpLn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udpLn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpLn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpLn.WriteTo(append([]byte("ECHO:"), buf[:n]...), from)
		}
	}()
	echoPort := udpLn.LocalAddr().(*net.UDPAddr).Port

	srv := &Server{
		UDPEnabled: true,
		NewEgress: func(ctx context.Context) (net.PacketConn, error) {
			return net.ListenPacket("udp4", "127.0.0.1:0")
		},
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go ServeLoop(ln, srv)

	// 1) TCP 控制连接 + UDP ASSOCIATE
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	_, _ = c.Write([]byte{5, 1, authNone})
	var mresp [2]byte
	if _, err := io.ReadFull(br, mresp[:]); err != nil {
		t.Fatalf("方法协商: %v", err)
	}
	req := []byte{5, cmdUDPAssociate, 0}
	req = append(req, writeTarget(Target{Host: "0.0.0.0", Port: 0})...)
	_, _ = c.Write(req)
	var rep [4]byte
	if _, err := io.ReadFull(br, rep[:]); err != nil {
		t.Fatalf("读 ASSOCIATE 应答: %v", err)
	}
	if rep[1] != repOK {
		t.Fatalf("ASSOCIATE 应答码 = %d", rep[1])
	}
	bnd, err := readTarget(br, rep[3])
	if err != nil {
		t.Fatalf("读 BND: %v", err)
	}
	if bnd.Port == 0 {
		t.Fatal("BND.PORT 不应为 0")
	}

	// 2) 发送经代理封装的 UDP 包
	payload := []byte("ping-1")
	wrapped := wrapUDP(Target{Host: "127.0.0.1", Port: echoPort}, payload)
	udpC, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", itoa(bnd.Port)))
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer udpC.Close()
	if _, err := udpC.Write(wrapped); err != nil {
		t.Fatalf("发送 UDP: %v", err)
	}

	// 3) 收回程（应带 ECHO: 前缀，且被正确封装）
	udpC.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := udpC.Read(buf)
	if err != nil {
		t.Fatalf("读回程 UDP: %v", err)
	}
	respPayload, respTgt, err := unwrapUDP(buf[:n])
	if err != nil {
		t.Fatalf("拆回程包: %v", err)
	}
	if !bytes.Equal(respPayload, append([]byte("ECHO:"), payload...)) {
		t.Fatalf("回程 payload 不一致: %q", respPayload)
	}
	if respTgt.Port != echoPort {
		t.Fatalf("回程目标端口不符: %d", respTgt.Port)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// ServeLoop 简单的监听循环，测试用。
func ServeLoop(ln net.Listener, srv *Server) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go srv.ServeConn(c, bufio.NewReader(c))
	}
}
