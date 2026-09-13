// Package httpproxy 实现 HTTP 代理（CONNECT 隧道与 absolute-form 普通请求转发）。
package httpproxy

import (
	"bufio"
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"lanrelay/internal/relay"
	"lanrelay/internal/stats"
)

const (
	headerTimeout  = 30 * time.Second
	dialTimeout    = 20 * time.Second
	connectTimeout = 20 * time.Second
)

// Server HTTP 代理服务端。
type Server struct {
	// Dial 出站拨号（绑定 PPPoE 接口、内置域名解析）
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ServeConn 处理一条已嗅探为 HTTP 的连接。
func (s *Server) ServeConn(c net.Conn, br *bufio.Reader) {
	stats.TCPActive.Add(1)
	defer stats.TCPActive.Add(-1)
	stats.ConnsTotal.Add(1)
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(headerTimeout))
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[http] %s 读取请求失败: %v", c.RemoteAddr(), err)
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(c, req)
		return
	}
	s.handleHTTP(c, req)
}

// handleConnect 处理 CONNECT 隧道（HTTPS 等）。
func (s *Server) handleConnect(c net.Conn, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.RequestURI
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443") // 缺省端口按 HTTPS 处理
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	remote, err := s.Dial(ctx, "tcp", host)
	if err != nil {
		log.Printf("[http] CONNECT %s 失败: %v", host, err)
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	log.Printf("[http] CONNECT %s 已建立（来自 %s）", host, c.RemoteAddr())
	relay.Pipe(c, remote)
}

// handleHTTP 转发 absolute-form 的普通 HTTP 请求（单请求后关闭）。
func (s *Server) handleHTTP(c net.Conn, req *http.Request) {
	if req.URL.Host == "" {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n本端口是代理端口，请使用绝对地址形式的请求（CONNECT 或 http://host/path）。\r\n"))
		return
	}
	tr := &http.Transport{
		DialContext:           s.Dial,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     true,
	}
	stripHopByHop(req)
	req.Close = true

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		log.Printf("[http] 转发 %s%s 失败: %v", req.Host, req.URL.Path, err)
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()
	if err := resp.Write(c); err != nil {
		log.Printf("[http] 回写响应失败: %v", err)
	}
}

var hopHeaders = []string{
	"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
	"Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(req *http.Request) {
	if conn := req.Header.Get("Connection"); conn != "" {
		for _, h := range strings.Split(conn, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				req.Header.Del(h)
			}
		}
	}
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}
	req.Header.Del("Connection")
}
