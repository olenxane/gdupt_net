//go:build windows

package bind

import "testing"

func TestHtonl(t *testing.T) {
	cases := map[int]int{
		12:      0x0c000000,
		70:      0x46000000,
		1:       0x01000000,
		0x10001: 0x01000100,
	}
	for in, want := range cases {
		if got := htonl(in); got != want {
			t.Fatalf("htonl(%d) = %#x, 期望 %#x", in, got, want)
		}
	}
}

func TestParseIPForms(t *testing.T) {
	if ip, err := parseIP("1.2.3.4:443"); err != nil || !ip.Is4() {
		t.Fatalf("parseIP 带端口失败: %v %v", ip, err)
	}
	if ip, err := parseIP("2001:db8::1"); err != nil || ip.Is4() {
		t.Fatalf("parseIP IPv6 失败: %v %v", ip, err)
	}
}
