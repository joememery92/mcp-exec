package mcp

import (
	"net/url"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// reconTool 把平台既有的侦察工具链（skills/recon/scripts/*.sh）搬到执行端执行。
//
// 与平台内 kind=command 自定义工具的区别只有一个：这里跑在节点上，产物写在工作区，
// 由控制端回传。参数名与脚本签名保持一致，因此技能与提示词不需要改写法。
func (s *Sandbox) reconTool() *Tool {
	return &Tool{
		Name: "recon",
		Description: "侦察工具链（在节点执行、结果落工作区）：\n" +
			"- subfind：被动子域枚举（subfinder），参数 domain[,max]\n" +
			"- portscan：TCP 端口发现（naabu），参数 target[,ports,rate]\n" +
			"- probe：HTTP 存活与指纹（ProjectDiscovery httpx），参数 target[,max]\n" +
			"- crawl：站点爬取（katana），参数 target[,depth]\n" +
			"- vulnscan：模板扫描（nuclei），参数 target[,severity]\n" +
			"用法 action=subfind target=example.com；长任务自动后台化并返回 job id。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":     map[string]any{"type": "string", "description": "subfind | portscan | probe | crawl | vulnscan"},
				"target":     map[string]any{"type": "string", "description": "目标（域、host、IP、CIDR 或文件路径）"},
				"workspace":  map[string]any{"type": "string", "description": "工作区名"},
				"extra":      map[string]any{"type": "string", "description": "可选第二参数：subfind=max、portscan=ports 或 rate、probe=max、crawl=depth、vulnscan=severity"},
				"background": map[string]any{"type": "boolean", "description": "强制后台执行（默认按 action 自动判断）"},
			},
			"required": []string{"action", "target", "workspace"},
		},
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			action := strings.ToLower(strings.TrimSpace(argString(args, "action")))
			target := strings.TrimSpace(argString(args, "target"))
			if target == "" {
				return "", fmt.Errorf("target 不能为空")
			}
			script, args2, background, err := s.reconCommand(action, target, argString(args, "extra"))
			if err != nil {
				return "", err
			}
			if b, ok := args["background"].(bool); ok {
				background = b
			}
			quoted := make([]string, 0, len(args2)+1)
			quoted = append(quoted, shellQuote(script))
			for _, a := range args2 {
				quoted = append(quoted, shellQuote(a))
			}
			// 输出同时落盘：长扫描的原始结果必须留在工作区里回传，不能只靠 stdout。
			outFile := filepath.Join("recon", fmt.Sprintf("%s-%s.txt", action, randomID()))
			if err := os.MkdirAll(filepath.Join(ws, "recon"), 0o755); err != nil {
				return "", err
			}
			command := fmt.Sprintf("%s | tee %s", strings.Join(quoted, " "), shellQuote(outFile))
			if background {
				started, err := s.startAsync(ctx, ws, command, s.MaxAsync)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s\n输出文件: %s（工作区内）", started, outFile), nil
			}
			out, err := s.runSync(ctx, ws, command, 90*time.Second)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s\n输出文件: %s（工作区内，已落盘可回传）\n提示：这类工具受目标响应速度影响，长时间无输出时改用 background=true 由 job_status 跟踪。", out, outFile), nil
		},
	}
}

// reconCommand 解析 action → 脚本路径与参数。脚本缺失时回落到同名二进制，
// 这样即使有人只装了工具没装脚本，执行端也不会整个瘫掉。
func (s *Sandbox) reconCommand(action, target, extra string) (string, []string, bool, error) {
	scriptDir := firstExistingDir(
		os.Getenv("MCPNODE_RECON_SCRIPTS"),
		"/opt/mcpnode/recon/scripts",
		"/opt/mcpnode/skills/recon/scripts",
	)
	name := ""
	background := false
	switch action {
	case "subfind", "subfinder":
		name, background = "subfind.sh", false
	case "portscan", "naabu":
		name, background = "portscan.sh", true
	case "probe", "httpx":
		name, background = "probe.sh", false
	case "crawl", "katana":
		name, background = "crawl.sh", true
	case "vulnscan", "nuclei":
		name, background = "vulnscan.sh", true
	default:
		return "", nil, false, fmt.Errorf("不支持的 action: %q", action)
	}
	script := filepath.Join(scriptDir, name)
	if _, err := os.Stat(script); err != nil {
		return "", nil, false, fmt.Errorf("侦察脚本缺失: %s（先运行 packaging/setup-recon.sh）", script)
	}
	argv := []string{target}
	switch {
	case extra != "":
		if action == "portscan" && strings.Contains(extra, "-") && !strings.Contains(extra, ",") {
			argv = append(argv, "", extra) // ports + rate 占位
		} else {
			argv = append(argv, extra)
		}
	}
	return script, argv, background, nil
}

func firstExistingDir(candidates ...string) string {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[len(candidates)-1]
	}
	return "/opt/mcpnode/recon/scripts"
}

// envCardTool 返回执行端的"环境自述"：工具在哪、出口是什么、工作区在哪、长任务怎么跑。
// 这一张卡片随上下文注入，模型不必靠猜（Cairn 的 container/AGENTS.md 就是这个作用）。
func (s *Sandbox) envCardTool() *Tool {
	return &Tool{
		Name:        "env_card",
		Description: "返回当前执行端的环境自述：主机、工作区、出口与代理、侦察工具版本与用法。开工前先读它。",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			ws := ""
			if name := argString(args, "workspace"); name != "" {
				if dir, err := s.workspace(name); err == nil {
					ws = dir
				}
			}
			host, _ := os.Hostname()
			var b strings.Builder
			fmt.Fprintf(&b, "# 执行端环境卡\n")
			fmt.Fprintf(&b, "节点: %s\n工作区根: %s\n", host, s.Root)
			if ws != "" {
				fmt.Fprintf(&b, "当前工作区: %s\n", ws)
			}
			fmt.Fprintf(&b, "对外 IP: %s\n", orDash(s.EgressIP))
			fmt.Fprintf(&b, "录制代理: %s（HTTP/HTTPS/ALL_PROXY 已注入）\n", describeProxy(s.Proxy))
			fmt.Fprintf(&b, "代理 CA: %s\n", orDash(s.CACert))
			fmt.Fprintf(&b, "同步 bash 上限: %s；后台任务上限: %s（bash_async + job_status/job_read/job_kill）\n",
				s.MaxSync, s.MaxAsync)
			fmt.Fprintf(&b, "侦察脚本: %s\n", firstExistingDir("/opt/mcpnode/recon/scripts"))
			fmt.Fprintf(&b, "工具版本:\n%s", s.toolVersions(ctx, ws))
			b.WriteString("约定:\n")
			b.WriteString("- 大输出一律落文件（recon 工具已自动 tee 到工作区 recon/ 下），别把几十万行塞进对话。\n")
			b.WriteString("- 需要持续运行的服务（接收反连、HTTP 服务）用 bash_async 起，并在结论里写清 job id 与端口。\n")
			b.WriteString("- 结论与原始数据分开：结论进事实图，原始数据留在工作区文件里，回传后可按路径复查。\n")
			return b.String(), nil
		},
	}
}

// describeProxy 只报「有没有配、什么协议、哪个端口」，不打印主机。
// 代理地址在部分部署形态下就是控制端的地址，没必要出现在工具输出里。
func describeProxy(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "-"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "已配置"
	}
	if u.Port() != "" {
		return u.Scheme + "://<录制端>:" + u.Port()
	}
	return u.Scheme + "://<录制端>"
}

func (s *Sandbox) toolVersions(ctx context.Context, ws string) string {
	if ws == "" {
		var err error
		ws, err = s.workspace(".envcard")
		if err != nil {
			return "  （无法创建工作区探测版本）\n"
		}
	}
	names := []string{"subfinder", "naabu", "httpx", "katana", "nuclei", "ffuf", "rg"}
	var b strings.Builder
	for _, n := range names {
		path := s.findBinary(n)
		if path == "" {
			fmt.Fprintf(&b, "  - %s: 未安装\n", n)
			continue
		}
		// PD 系列工具会先打一段 ASCII banner，版本号在后面几行，所以多取几行再按正则挑。
		out, _ := s.runSync(ctx, ws, shellQuote(path)+" -version 2>&1 | head -12 || true", 15*time.Second)
		fmt.Fprintf(&b, "  - %s: %s (%s)\n", n, extractVersion(out), path)
	}
	return b.String()
}

var versionRe = regexp.MustCompile(`v?[0-9]+\.[0-9]+\.[0-9]+`)

// extractVersion 从工具输出里挑版本号。工具输出前面总有我们自己的命令行头部
// （"$ …" 与状态行），且 ProjectDiscovery 一类工具会先打 ASCII banner，
// 因此不能简单取第一行——那会把"命令本身"当成版本显示出来。
func extractVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "$ ") || strings.HasPrefix(line, "(") {
			continue
		}
		if v := versionRe.FindString(line); v != "" {
			return v
		}
	}
	return "已安装（版本未知）"
}

func (s *Sandbox) findBinary(name string) string {
	candidates := []string{
		filepath.Join(s.Root, "..", "tools", name),
		"/opt/mcpnode/data/tools/" + name,
		"/usr/local/bin/" + name,
		"/usr/bin/" + name,
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return c
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}
