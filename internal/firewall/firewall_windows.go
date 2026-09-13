//go:build windows

// Package firewall 确保代理端口在 Windows 防火墙放行（限定局域网）。
package firewall

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

// IsElevated 当前进程是否以管理员运行。
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Rule 一条入站放行规则。
type Rule struct {
	Name     string
	Protocol string // TCP / UDP
	Port     int
}

// Ensure 检查并按需添加放行规则，限定 remoteip=localsubnet。
// 返回：已添加的规则名、缺失且未能自动添加的规则名、错误。
func Ensure(rules []Rule) (added, manual []string, err error) {
	for _, r := range rules {
		exists, exErr := ruleExists(r.Name)
		if exErr == nil && exists {
			continue
		}
		if !IsElevated() {
			manual = append(manual, r.Name)
			continue
		}
		args := []string{
			"advfirewall", "firewall", "add", "rule",
			"name=" + r.Name,
			"dir=in", "action=allow",
			"protocol=" + r.Protocol,
			"localport=" + fmt.Sprint(r.Port),
			"remoteip=localsubnet",
			"profile=any",
		}
		cmd := exec.Command("netsh", args...)
		cmd.SysProcAttr = hideWindow()
		if out, rErr := cmd.CombinedOutput(); rErr != nil {
			return added, manual, fmt.Errorf("添加防火墙规则 %s 失败: %v: %s", r.Name, rErr, strings.TrimSpace(string(out)))
		}
		added = append(added, r.Name)
	}
	return added, manual, nil
}

// ManualCommand 未提权时的手动命令。
func ManualCommand(r Rule) string {
	return fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=%s localport=%d remoteip=localsubnet profile=any`,
		r.Name, r.Protocol, r.Port)
}

func ruleExists(name string) (bool, error) {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+name)
	cmd.SysProcAttr = hideWindow()
	out, err := cmd.CombinedOutput()
	if err != nil {
		// 规则不存在时 netsh 退出码非 0
		return false, nil
	}
	return strings.Contains(string(out), name), nil
}
