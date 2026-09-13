package mixed

import "testing"

func TestIsSocks5(t *testing.T) {
	cases := map[[1]byte]bool{
		{0x05}: true,  // SOCKS5 版本字节
		{'G'}:  false, // GET...
		{'C'}:  false, // CONNECT
		{0x16}: false, // TLS ClientHello
		{0x04}: false, // SOCKS4
	}
	for in, want := range cases {
		if got := IsSocks5(in[:]); got != want {
			t.Fatalf("IsSocks5(%#x) = %v, 期望 %v", in[0], got, want)
		}
	}
}
