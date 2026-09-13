// Package mixed 实现单端口混合代理：按连接首字节嗅探 SOCKS5 与 HTTP 协议。
package mixed

import (
	"bufio"
	"io"
	"log"
	"net"
)

// Handler 协议处理器，br 中可能已缓冲嗅探阶段读取的数据，必须继续从 br 读取。
type Handler func(c net.Conn, br *bufio.Reader)

// Serve 接受连接并按协议分发。
func Serve(ln net.Listener, socksH, httpH Handler) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if isTemporary(err) {
				continue
			}
			return
		}
		go Handle(c, socksH, httpH)
	}
}

// Handle 对单条连接做协议嗅探并分发。
func Handle(c net.Conn, socksH, httpH Handler) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 8192)
	head, err := br.Peek(1)
	if err != nil {
		if err != io.EOF {
			log.Printf("[mixed] %s 嗅探读取失败: %v", c.RemoteAddr(), err)
		}
		return
	}
	if IsSocks5(head) {
		socksH(c, br)
		return
	}
	httpH(c, br)
}

// IsSocks5 依据首字节判断：SOCKS5 版本字节为 0x05。
func IsSocks5(head []byte) bool {
	return len(head) > 0 && head[0] == 0x05
}

func isTemporary(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
