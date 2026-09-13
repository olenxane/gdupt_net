package relay

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"lanrelay/internal/stats"
)

// setupRelay 用两层 net.Pipe 构造：测试持有两端外侧（clientEnd / remoteEnd），
// relay.Pipe 持有内侧，从而可在测试中同时观察两个方向。
func setupRelay(t *testing.T) (clientEnd, remoteEnd net.Conn) {
	t.Helper()
	ca, cb := net.Pipe()
	ra, rb := net.Pipe()
	go Pipe(cb, ra) // cb = 客户端内侧, ra = 远端内侧
	t.Cleanup(func() {
		ca.Close()
		cb.Close()
		ra.Close()
		rb.Close()
	})
	return ca, rb
}

func TestPipeBidirectional(t *testing.T) {
	clientEnd, remoteEnd := setupRelay(t)

	msgA := bytes.Repeat([]byte("A->B "), 10000)
	msgB := bytes.Repeat([]byte("B->A "), 10000)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, len(msgB))
		if _, err := io.ReadFull(clientEnd, buf); err != nil {
			t.Errorf("读 B→A: %v", err)
			return
		}
		if !bytes.Equal(buf, msgB) {
			t.Errorf("B→A 数据不一致")
		}
	}()

	// 上行：clientEnd 写入 → remoteEnd 读出
	go func() { _, _ = clientEnd.Write(msgA) }()
	remoteEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	gotA := make([]byte, len(msgA))
	if _, err := io.ReadFull(remoteEnd, gotA); err != nil {
		t.Fatalf("读 A→B: %v", err)
	}
	if !bytes.Equal(gotA, msgA) {
		t.Fatal("A→B 数据不一致")
	}

	// 下行：remoteEnd 写入 → clientEnd 读出
	go func() { _, _ = remoteEnd.Write(msgB) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("下行超时")
	}
}

func TestPipeStatsAndClose(t *testing.T) {
	clientEnd, remoteEnd := setupRelay(t)
	upBefore := stats.BytesUp.Load()

	if _, err := clientEnd.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	remoteEnd.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(remoteEnd, buf); err != nil {
		t.Fatalf("读上行数据: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if stats.BytesUp.Load()-upBefore >= 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := stats.BytesUp.Load() - upBefore; got != 5 {
		t.Fatalf("上行统计 = %d, 期望 5", got)
	}

	// 远端关闭后，Pipe 应关闭客户端侧连接
	remoteEnd.Close()
	if _, err := clientEnd.Write([]byte("x")); err == nil {
		// net.Pipe 的写可能先阻塞，再因对端关闭而失败；再给一点时间
		time.Sleep(200 * time.Millisecond)
		if _, err := clientEnd.Write([]byte("y")); err == nil {
			t.Fatal("客户端连接应已被关闭")
		}
	}
}
