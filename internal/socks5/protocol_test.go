package socks5

import (
	"bytes"
	"net"
	"testing"
)

func TestTargetRoundTrip(t *testing.T) {
	cases := []Target{
		{Host: "1.2.3.4", Port: 443},
		{Host: "example.com", Port: 80},
		{Host: "2001:db8::1", Port: 8080},
	}
	for _, c := range cases {
		b := writeTarget(c) // ATYP + ADDR + PORT
		got, err := readTarget(bytes.NewReader(b[1:]), b[0])
		if err != nil {
			t.Fatalf("readTarget(%s): %v", c, err)
		}
		if got.Host != c.Host || got.Port != c.Port {
			t.Fatalf("往返不一致: 期望 %v 实际 %v", c, got)
		}
	}
}

func TestReadTargetBadATYP(t *testing.T) {
	if _, err := readTarget(bytes.NewReader([]byte{1, 2, 3}), 9); err == nil {
		t.Fatal("非法 ATYP 应报错")
	}
}

func TestWriteReplyOK(t *testing.T) {
	var buf bytes.Buffer
	if err := writeReply(&buf, repOK, net.IPv4(192, 168, 25, 177), 54321); err != nil {
		t.Fatalf("writeReply: %v", err)
	}
	want := []byte{5, 0, 0, 1, 192, 168, 25, 177, 0xd4, 0x31}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("应答字节不符: 期望 %v 实际 %v", want, buf.Bytes())
	}
}

func TestWriteReplyFailure(t *testing.T) {
	var buf bytes.Buffer
	_ = writeReply(&buf, repConnRefused, net.IPv4(1, 2, 3, 4), 1)
	want := []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("失败应答 BND 应为 0: %v", buf.Bytes())
	}
}

func TestUDPWrapUnwrap(t *testing.T) {
	orig := []byte("hello udp payload")
	tgt := Target{Host: "223.5.5.5", Port: 53}
	wrapped := wrapUDP(tgt, orig)
	payload, got, err := unwrapUDP(wrapped)
	if err != nil {
		t.Fatalf("unwrapUDP: %v", err)
	}
	if !bytes.Equal(payload, orig) {
		t.Fatalf("payload 不一致: %q", payload)
	}
	if got.Host != tgt.Host || got.Port != tgt.Port {
		t.Fatalf("目标不一致: %v vs %v", got, tgt)
	}
}

func TestUnwrapUDPFragmentRejected(t *testing.T) {
	b := []byte{0, 0, 2, 1, 8, 8, 8, 8, 0, 53}
	if _, _, err := unwrapUDP(b); err == nil {
		t.Fatal("FRAG!=0 应报错")
	}
}
