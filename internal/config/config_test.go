package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingUsesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "no-such.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenPort != 7890 || c.AdminPort != 9090 || !c.UDP || c.WAN != "auto" {
		t.Fatalf("默认配置不符: %+v", c)
	}
}

func TestLoadOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.yaml")
	body := `
listen: WLAN
listen_port: 1080
wan: 校园网
udp: false
quic_block: true
auth:
  username: alice
  password: secret
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != "WLAN" || c.ListenPort != 1080 || c.WAN != "校园网" || c.UDP || !c.QUICBlock {
		t.Fatalf("覆盖配置不符: %+v", c)
	}
	if !c.HasAuth() || c.Auth.Username != "alice" || c.Auth.Password != "secret" {
		t.Fatalf("认证配置不符: %+v", c.Auth)
	}
}

func TestWriteDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "relay-config.yaml")
	if err := WriteDefault(path); err != nil {
		t.Fatalf("WriteDefault: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("默认配置未写出: %v", err)
	}
	if err := WriteDefault(path); err == nil {
		t.Fatal("已存在时应报错")
	}
}
