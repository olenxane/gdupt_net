// Package relay 提供双向流拷贝（带缓冲池与流量统计）。
package relay

import (
	"io"
	"net"
	"sync"

	"lanrelay/internal/stats"
)

const bufSize = 64 * 1024

var bufPool = sync.Pool{
	New: func() any { b := make([]byte, bufSize); return &b },
}

// upDown 区分流量方向：up = 客户端 → 远端，down = 远端 → 客户端。
type upDown int

const (
	dirUp upDown = iota
	dirDown
)

type countedConn struct {
	net.Conn
	dir upDown
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if c.dir == dirUp {
			stats.BytesUp.Add(int64(n))
		} else {
			stats.BytesDown.Add(int64(n))
		}
	}
	return n, err
}

// Pipe 在 client 与 remote 之间双向拷贝，任一方向出错即关闭两端。
// client 为客户端侧连接：client 读到的字节计为上行，写给 client 的计为下行。
func Pipe(client, remote net.Conn) {
	done := make(chan struct{}, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			client.Close()
			remote.Close()
		})
	}

	copyFn := func(dst net.Conn, src *countedConn) {
		defer func() { done <- struct{}{}; closeBoth() }()
		bufp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufp)
		// src 已包裹计数，dst 直接写
		_, _ = io.CopyBuffer(dst, src, *bufp)
		// 半关闭：将本方向 EOF 传导给对端
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	go copyFn(remote, &countedConn{Conn: client, dir: dirUp})
	go copyFn(client, &countedConn{Conn: remote, dir: dirDown})
	<-done
	<-done
}
