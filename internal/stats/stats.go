// Package stats 提供进程级流量与连接计数。
package stats

import "sync/atomic"

var (
	// TCPActive 当前活跃的 TCP 隧道数。
	TCPActive atomic.Int64
	// UDPActive 当前活跃的 UDP 中转会话数。
	UDPActive atomic.Int64
	// BytesUp 客户端 → 互联网 方向的累计字节数。
	BytesUp atomic.Int64
	// BytesDown 互联网 → 客户端 方向的累计字节数。
	BytesDown atomic.Int64
	// ConnsTotal 累计处理的 TCP 连接数。
	ConnsTotal atomic.Int64
)
