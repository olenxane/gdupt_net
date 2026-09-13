// Package config 负责中转程序的配置加载与默认值。
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Version 程序版本号。
const Version = "1.0.0"

// Auth 代理认证（留空表示无认证）。
type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Config 中转程序配置。
type Config struct {
	// Listen 入站适配器：auto / 适配器名(如 WLAN) / ifIndex / IP 地址
	Listen string `yaml:"listen"`
	// ListenPort 代理监听端口（SOCKS5 与 HTTP 混合嗅探）
	ListenPort int `yaml:"listen_port"`
	// AdminPort 状态页与 Clash 配置下载端口，0 表示禁用
	AdminPort int `yaml:"admin_port"`
	// WAN 出站适配器：auto / 适配器名(如 校园网) / ifIndex
	WAN string `yaml:"wan"`
	// UDP 是否启用 SOCKS5 UDP 中转（DNS、QUIC、游戏等）
	UDP bool `yaml:"udp"`
	// DNSServers 出站 DNS 服务器，为空则使用 WAN 适配器系统 DNS，仍为空时回落 223.5.5.5/119.29.29.29
	DNSServers []string `yaml:"dns_servers"`
	// AllowCIDRs 客户端来源白名单（CIDR），为空不限制
	AllowCIDRs []string `yaml:"allow_cidrs"`
	// Auth 认证，默认无认证
	Auth Auth `yaml:"auth"`
	// QUICBlock 丢弃 UDP 443 端口的流量，迫使客户端回落 TCP
	QUICBlock bool `yaml:"quic_block"`
	// PollSecs 适配器状态轮询间隔（秒）
	PollSecs int `yaml:"poll_secs"`
	// LogFile 日志文件，为空仅输出到控制台
	LogFile string `yaml:"log_file"`
}

// Default 返回默认配置。
func Default() *Config {
	return &Config{
		Listen:     "auto",
		ListenPort: 7890,
		AdminPort:  9090,
		WAN:        "auto",
		UDP:        true,
		PollSecs:   5,
	}
}

// Load 从 YAML 文件加载配置；文件不存在时返回默认配置。
func Load(path string) (*Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			c.normalize()
			return c, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, err)
	}
	c.normalize()
	return c, nil
}

// WriteDefault 将带注释的默认配置写入 path（已存在时不覆盖）。
func WriteDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("配置已存在: %s", path)
	}
	body := `# LAN 中转网关配置（lan-relay）
# 入站适配器：auto 自动选择（优先 WLAN 类无线网卡），也可填适配器名 / ifIndex / IP
listen: auto
# 代理监听端口：SOCKS5 与 HTTP 混合端口（按首字节自动嗅探协议）
listen_port: 7890
# 状态页端口：浏览器打开 http://<本机LAN IP>:9090/ 查看流量，/clash.yaml 下载手机端配置；0 禁用
admin_port: 9090
# 出站适配器：auto 自动选择（优先 PPP 拨号适配器，如「校园网」），也可填适配器名 / ifIndex
wan: auto
# 启用 SOCKS5 UDP 中转（DNS 解析、QUIC/HTTP3、游戏联机需要）
udp: true
# 出站 DNS 服务器：留空使用宽带适配器的系统 DNS
dns_servers: []
# 客户端来源白名单（CIDR），留空不限制
allow_cidrs: []
# 代理认证：留空表示无认证（默认）
auth:
  username: ""
  password: ""
# 丢弃 UDP 443（QUIC/HTTP3）迫使客户端走 TCP，个别出口屏蔽 UDP 时可开启
quic_block: false
# 适配器轮询间隔（秒）：监测 PPPoE 重拨换 IP、WLAN 掉线重连
poll_secs: 5
# 日志文件：留空仅输出控制台
log_file: ""
`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

func (c *Config) normalize() {
	if c.Listen == "" {
		c.Listen = "auto"
	}
	if c.WAN == "" {
		c.WAN = "auto"
	}
	if c.ListenPort == 0 {
		c.ListenPort = 7890
	}
	if c.PollSecs <= 0 {
		c.PollSecs = 5
	}
}

// HasAuth 是否启用了账号密码认证。
func (c *Config) HasAuth() bool {
	return c.Auth.Username != "" || c.Auth.Password != ""
}
