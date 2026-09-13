// relayprobe —— lan-relay 全链路探测工具。
//
// 通过 SOCKS5 代理验证两条路径：
//   tcp 模式：CONNECT 隧道 + HTTP GET（验证 TCP 出站）
//   udp 模式：UDP ASSOCIATE + DNS 查询（验证 UDP 中转）
//
// 用法：
//   relayprobe -proxy 192.168.25.177:7890 -mode tcp -host ifconfig.me
//   relayprobe -proxy 192.168.25.177:7890 -mode udp -domain www.baidu.com
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	proxy := flag.String("proxy", "127.0.0.1:7890", "代理地址 host:port")
	mode := flag.String("mode", "tcp", "探测模式: tcp / udp")
	host := flag.String("host", "ifconfig.me", "tcp 模式目标主机")
	port := flag.Int("port", 80, "tcp 模式目标端口")
	domain := flag.String("domain", "www.baidu.com", "udp 模式查询的域名")
	timeout := flag.Duration("timeout", 15*time.Second, "超时")
	flag.Parse()

	var err error
	switch *mode {
	case "tcp":
		err = probeTCP(*proxy, *host, *port, *timeout)
	case "udp":
		err = probeUDP(*proxy, *domain, *timeout)
	default:
		err = fmt.Errorf("未知模式 %q（可选 tcp / udp）", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "探测失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("探测成功")
}

// socks5Dial 建立到代理的 TCP 连接并完成无认证握手。
func socks5Dial(proxy string, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp4", proxy, timeout)
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s: %w", proxy, err)
	}
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("方法协商: %w", err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("方法协商应答异常: %v", resp)
	}
	return c, nil
}

func writeTarget(host string, port int) []byte {
	var out []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		out = append(out, 1)
		out = append(out, ip.To4()...)
	} else if ip := net.ParseIP(host); ip != nil {
		out = append(out, 4)
		out = append(out, ip.To16()...)
	} else {
		out = append(out, 3, byte(len(host)))
		out = append(out, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	return append(out, p[:]...)
}

func readReply(br io.Reader) (rep byte, bndHost string, bndPort int, err error) {
	var head [4]byte
	if _, err = io.ReadFull(br, head[:]); err != nil {
		return
	}
	if head[0] != 5 {
		err = fmt.Errorf("应答版本 %d", head[0])
		return
	}
	rep = head[1]
	var host string
	switch head[3] {
	case 1:
		var b [4]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case 3:
		var l [1]byte
		if _, err = io.ReadFull(br, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		var b [16]byte
		if _, err = io.ReadFull(br, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	default:
		err = fmt.Errorf("应答地址类型 %d", head[3])
		return
	}
	var p [2]byte
	if _, err = io.ReadFull(br, p[:]); err != nil {
		return
	}
	return rep, host, int(binary.BigEndian.Uint16(p[:])), nil
}

func probeTCP(proxy, host string, port int, timeout time.Duration) error {
	c, err := socks5Dial(proxy, timeout)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, err := c.Write(append([]byte{5, 1, 0}, writeTarget(host, port)...)); err != nil {
		return err
	}
	rep, _, _, err := readReply(c)
	if err != nil {
		return fmt.Errorf("CONNECT 应答: %w", err)
	}
	if rep != 0 {
		return fmt.Errorf("CONNECT 应答码 %d", rep)
	}
	fmt.Printf("TCP 隧道已建立: %s:%d\n", host, port)

	c.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: relayprobe\r\n\r\n", host)
	if _, err := c.Write([]byte(req)); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil && n == 0 {
		return fmt.Errorf("读取响应: %w", err)
	}
	head := string(buf[:n])
	fmt.Println(strings.Repeat("-", 46))
	fmt.Println(strings.TrimSpace(head))
	fmt.Println(strings.Repeat("-", 46))
	if !strings.Contains(head, "HTTP/1.") {
		return fmt.Errorf("响应不像 HTTP")
	}
	return nil
}

func probeUDP(proxy, domain string, timeout time.Duration) error {
	c, err := socks5Dial(proxy, timeout)
	if err != nil {
		return err
	}
	defer c.Close()

	// UDP ASSOCIATE（DST 0.0.0.0:0）
	if _, err := c.Write(append([]byte{5, 3, 0}, writeTarget("0.0.0.0", 0)...)); err != nil {
		return err
	}
	rep, bndHost, bndPort, err := readReply(c)
	if err != nil {
		return fmt.Errorf("UDP ASSOCIATE 应答: %w", err)
	}
	if rep != 0 {
		return fmt.Errorf("UDP ASSOCIATE 应答码 %d", rep)
	}
	if bndHost == "0.0.0.0" {
		bndHost = strings.Split(proxy, ":")[0]
	}
	fmt.Printf("UDP 中转端点: %s:%d\n", bndHost, bndPort)

	udp, err := net.Dial("udp4", net.JoinHostPort(bndHost, fmt.Sprint(bndPort)))
	if err != nil {
		return err
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(timeout))

	// 构造 DNS A 查询
	q := buildDNSQuery(domain)
	wrapped := append([]byte{0, 0, 0}, writeTarget("223.5.5.5", 53)...)
	wrapped = append(wrapped, q...)
	if _, err := udp.Write(wrapped); err != nil {
		return fmt.Errorf("发送 DNS 查询: %w", err)
	}

	buf := make([]byte, 2048)
	n, err := udp.Read(buf)
	if err != nil {
		return fmt.Errorf("读取 DNS 响应: %w", err)
	}
	if n < 4+1+2+2 { // 头 + 至少 1 域名 + qtype + qclass
		return fmt.Errorf("响应过短: %d 字节", n)
	}
	payload, tgt, err := unwrapProbe(buf[:n])
	if err != nil {
		return err
	}
	fmt.Printf("回程来源: %s\n", tgt)
	answers := int(binary.BigEndian.Uint16(payload[6:8]))
	rcode := payload[3] & 0x0F
	fmt.Printf("DNS 响应: RCODE=%d, ANSWER=%d\n", rcode, answers)
	if rcode != 0 || answers == 0 {
		return fmt.Errorf("DNS 查询未成功")
	}
	// 提取第一个 A 记录地址（简化：搜索最后一个 4 字节作为答案 IP）
	ip := extractFirstA(payload, len(q))
	if ip != "" {
		fmt.Printf("%s -> %s\n", domain, ip)
	}
	return nil
}

func unwrapProbe(b []byte) (payload []byte, tgt string, err error) {
	if len(b) < 4 || b[2] != 0 {
		return nil, "", fmt.Errorf("回程包格式错误")
	}
	atyp := b[3]
	off := 4
	var host string
	switch atyp {
	case 1:
		if len(b) < off+4 {
			return nil, "", fmt.Errorf("包过短")
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case 4:
		if len(b) < off+16 {
			return nil, "", fmt.Errorf("包过短")
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	case 3:
		if len(b) < off+1 {
			return nil, "", fmt.Errorf("包过短")
		}
		l := int(b[off])
		off++
		if len(b) < off+l {
			return nil, "", fmt.Errorf("包过短")
		}
		host = string(b[off : off+l])
		off += l
	default:
		return nil, "", fmt.Errorf("回程地址类型 %d", atyp)
	}
	if len(b) < off+2 {
		return nil, "", fmt.Errorf("包过短")
	}
	port := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	return b[off:], net.JoinHostPort(host, fmt.Sprint(port)), nil
}

func buildDNSQuery(domain string) []byte {
	var b []byte
	id := uint16(rand.Intn(0xFFFF))
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	b = append(b, hdr...)
	for _, label := range strings.Split(domain, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = append(b, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	return b
}

func extractFirstA(payload []byte, queryLen int) string {
	if len(payload) < queryLen+12 {
		return ""
	}
	// 答案区从 queryLen 开始：NAME(压缩 0xC00C) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA
	rest := payload[queryLen:]
	// 跳过 NAME 指针或名称
	if len(rest) < 2 {
		return ""
	}
	if rest[0]&0xC0 == 0xC0 {
		rest = rest[2:]
	}
	if len(rest) < 10 {
		return ""
	}
	if binary.BigEndian.Uint16(rest[0:2]) != 1 { // TYPE != A
		return ""
	}
	rdlen := int(binary.BigEndian.Uint16(rest[8:10]))
	if rdlen != 4 || len(rest) < 10+4 {
		return ""
	}
	return net.IP(rest[10 : 10+4]).String()
}
