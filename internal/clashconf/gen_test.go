package clashconf

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerate(t *testing.T) {
	out := Generate("192.168.25.177", 7890, "", "")
	checks := []string{
		"mode: global",
		"- MATCH,PC-Relay",
		"server: 192.168.25.177",
		"port: 7890",
		"udp: true",
		"enhanced-mode: fake-ip",
		"'223.5.5.5#PC-Relay'",
		"type: socks5",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Fatalf("生成的配置缺少 %q\n---\n%s", want, out)
		}
	}
}

func TestGenerateWithAuth(t *testing.T) {
	out := Generate("10.0.0.1", 1080, "alice", "wonderland")
	if !strings.Contains(out, "username: alice") || !strings.Contains(out, "password: wonderland") {
		t.Fatalf("认证信息未写入:\n%s", out)
	}
}

func TestGenerateNoAuth(t *testing.T) {
	out := Generate("10.0.0.1", 7890, "", "")
	if strings.Contains(out, "username:") {
		t.Fatalf("无认证时不应有 username 行:\n%s", out)
	}
}

// TestGenerateValidYAML 保证生成的配置可被标准 YAML 解析器解析（mihomo 兼容底线）。
func TestGenerateValidYAML(t *testing.T) {
	for _, tc := range []struct{ server, user, pass string }{
		{"192.168.25.177", "", ""},
		{"192.168.25.177", "alice", "wonderland"},
		{"10.255.255.10", "", ""},
	} {
		out := Generate(tc.server, 7890, tc.user, tc.pass)
		var m map[string]any
		if err := yaml.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("生成的配置不是合法 YAML: %v\n---\n%s", err, out)
		}
		proxies, ok := m["proxies"].([]any)
		if !ok || len(proxies) != 1 {
			t.Fatalf("proxies 结构错误: %#v", m["proxies"])
		}
		p0 := proxies[0].(map[string]any)
		if p0["server"] != tc.server || p0["udp"] != true {
			t.Fatalf("proxy 节点字段错误: %#v", p0)
		}
		rules := m["rules"].([]any)
		if len(rules) != 1 || rules[0] != "MATCH,PC-Relay" {
			t.Fatalf("rules 应仅含 MATCH 兜底: %#v", rules)
		}
		if m["mode"] != "global" {
			t.Fatalf("mode 应为 global: %#v", m["mode"])
		}
	}
}
