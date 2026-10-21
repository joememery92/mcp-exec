// announce.go —— 节点自报：让「没有 SSH、可能没有公网入站」的执行节点（免费容器、
// 家宽机器）自己把 MCP 地址汇报给控制端。
//
// 与「控制端主动注册」（手工登记 + SSH 隧道）的分工：那条路要求控制端能连到
// 节点，所以必须有隧道或公网入口；自报只需要节点能出网到控制端，唯一的凭据是注册
// 令牌（由控制端签发）。
//
// 两个刻意的取舍：
//   - 自报请求与出口 IP 探测**不走录制代理**：录制代理是给目标流量用的（要进流量库），
//     控制端自己的注册接口不该混进去；而且经代理探测到的"出口 IP"会是代理的 IP，
//     跟节点自己的可达地址不是一回事。
//   - 自报失败绝不影响沙箱本体：MCP 端点照常提供服务，操作者仍然可以手工登记
//     手动注册这台节点（自报只是省掉了这一步）。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	// announceInterval 是周期自报的间隔：容器重建 / 家宽换 IP / 隧道换域名之后，
	// 控制端会在一个周期内自动跟上，不需要人工改库。
	announceInterval = 5 * time.Minute
	// announceAttempts 与 announceBackoff 决定单轮重试：首次立即试，之后 5s、10s
	// （指数退避），三次都失败就等下一个周期——容器启动早于控制端可达是常态。
	announceAttempts     = 3
	announceBackoff      = 5 * time.Second
	announceProbeTimeout = 8 * time.Second
	announceHTTPTimeout  = 20 * time.Second
	announceMaxBody      = 4096
)

// egressIPProbeURLs 是探测出口 IP 的服务，按顺序试；全是失败时不猜地址，只提示
// 操作者用 -announce-url 显式给出对外地址。
var egressIPProbeURLs = []string{"https://api.ipify.org", "https://ifconfig.me/ip"}

// nodeNameRe 与控制端（db.sandboxNodeNameRe）保持一致；名字会被拼进 MCP 数据源名与
// systemd 单元名，所以不能出现大写、下划线或空格。
var nodeNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// announceConfig 是自报所需的全部参数。
type announceConfig struct {
	ControlURL   string   // 控制端根地址，如 http://127.0.0.1:8787
	Name         string   // 节点名（[a-z0-9-]+）
	EnrollToken  string   // 注册令牌（控制端注册令牌接口）
	MCPURL       string   // 本节点对外可达的 MCP 地址；空 = 用出口 IP + 监听端口拼
	Labels       []string // 能力标签（可空）
	SandboxToken string   // 本节点自己的调用令牌，控制端据此调用它（可空 = 无令牌节点）
}

// announcer 持有自报状态。所有方法都假定 Run 只被调用一次。
type announcer struct {
	cfg        announceConfig
	listenAddr string
	client     *http.Client
}

// newAnnouncer 组装自报器。client 不走任何代理（含环境变量里的 HTTP_PROXY），
// 理由见文件头。
func newAnnouncer(cfg announceConfig, listenAddr string) *announcer {
	return &announcer{
		cfg:        cfg,
		listenAddr: listenAddr,
		client: &http.Client{
			Timeout:   announceHTTPTimeout,
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

// announceConfigFromFlags 把命令行参数收敛成一份配置；返回 nil 表示没开自报。
//
// 令牌优先级与沙箱令牌一致：flag > 文件 > 空。缺令牌时返回 nil + 错误提示——自报
// 没有令牌必然 401，与其每 5 分钟打一行失败日志，不如一次说清楚（沙箱本体照常服务）。
func announceConfigFromFlags(control, name, token, tokenFile, url, labels string) (*announceConfig, string) {
	control = strings.TrimSpace(control)
	if control == "" {
		return nil, ""
	}
	if !strings.HasPrefix(control, "http://") && !strings.HasPrefix(control, "https://") {
		control = "http://" + control
	}
	enroll := strings.TrimSpace(token)
	if enroll == "" && strings.TrimSpace(tokenFile) != "" {
		data, err := os.ReadFile(strings.TrimSpace(tokenFile))
		if err != nil {
			return nil, fmt.Sprintf("读取注册令牌文件失败: %v", err)
		}
		enroll = strings.TrimSpace(string(data))
	}
	if enroll == "" {
		return nil, "未提供注册令牌：自报已禁用（向控制端索取注册令牌，再用 -announce-token-file 传入）"
	}
	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" {
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Sprintf("取主机名失败（请显式给 -announce-name）: %v", err)
		}
		resolvedName = sanitizeNodeName(host)
	}
	if resolvedName == "" {
		return nil, "节点名为空（请显式给 -announce-name，只允许 [a-z0-9-]）"
	}
	// 显式给的名字不替用户「修正」：控制端的校验是权威（同一套正则），在这里提前
	// 失败只是把「每 5 分钟一次 400」变成启动时一句能看懂的话。
	if !nodeNameRe.MatchString(resolvedName) {
		return nil, fmt.Sprintf("节点名 %q 非法：只允许小写字母、数字与连字符（例如 free-node-1）", resolvedName)
	}
	return &announceConfig{
		ControlURL:  control,
		Name:        resolvedName,
		EnrollToken: enroll,
		MCPURL:      strings.TrimSpace(url),
		Labels:      splitCommaList(labels),
	}, ""
}

// run 先自报一次，之后每 announceInterval 上报一次，直到 ctx 结束。
func (a *announcer) run(ctx context.Context) {
	if err := a.announceWithRetry(ctx); err != nil && ctx.Err() == nil {
		log.Printf("[announce] 自报失败：%v", err)
	}
	ticker := time.NewTicker(announceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.announceWithRetry(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[announce] 自报失败：%v", err)
			}
		}
	}
}

// announceWithRetry 最多尝试 announceAttempts 次，间隔按 announceBackoff 指数退避。
func (a *announcer) announceWithRetry(ctx context.Context) error {
	wait := announceBackoff
	var lastErr error
	for attempt := 1; attempt <= announceAttempts; attempt++ {
		mcpURL, created, err := a.announceOnce(ctx)
		if err == nil {
			verb := "已更新"
			if created {
				verb = "已注册"
			}
			log.Printf("[announce] %s节点 %s：%s（控制端 %s）", verb, a.cfg.Name, mcpURL, a.cfg.ControlURL)
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= announceAttempts {
			break
		}
		log.Printf("[announce] 第 %d/%d 次失败：%v（%v 后重试）", attempt, announceAttempts, err, wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
	return lastErr
}

// announceOnce 上报一次，返回最终使用的 MCP 地址与控制端是否新建了节点。
func (a *announcer) announceOnce(ctx context.Context) (string, bool, error) {
	mcpURL, err := a.resolveMCPURL(ctx)
	if err != nil {
		return "", false, err
	}
	payload, err := json.Marshal(struct {
		Name   string   `json:"name"`
		MCPURL string   `json:"mcp_url"`
		Labels []string `json:"labels"`
		Token  string   `json:"token"`
	}{a.cfg.Name, mcpURL, a.cfg.Labels, a.cfg.SandboxToken})
	if err != nil {
		return "", false, err
	}
	endpoint := strings.TrimRight(a.cfg.ControlURL, "/") + "/api/nodes/announce"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enroll-Token", a.cfg.EnrollToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, announceMaxBody))
	if resp.StatusCode == http.StatusUnauthorized {
		return "", false, errors.New("注册令牌被拒（401）：在控制端跑 向控制端索取当前注册令牌；令牌轮换后需要重新下发")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", false, fmt.Errorf("来源 IP 已被限流（429）：撞令牌不会换来访问权，先确认令牌正确（%s）", resp.Header.Get("Retry-After"))
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("控制端返回 %s: %s", resp.Status, truncateBody(raw))
	}
	var out struct {
		ID      int64 `json:"id"`
		Created bool  `json:"created"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", false, fmt.Errorf("控制端响应无法解析: %w（%s）", err, truncateBody(raw))
	}
	return mcpURL, out.Created, nil
}

// resolveMCPURL 得到本节点对外可达的 MCP 地址：显式给了就用，否则探测出口 IP 并
// 配上监听端口。探测失败时不猜——猜出来的地址注册进控制端只会变成一个连不上的节点。
func (a *announcer) resolveMCPURL(ctx context.Context) (string, error) {
	if a.cfg.MCPURL != "" {
		return a.cfg.MCPURL, nil
	}
	ip, err := a.egressIP(ctx)
	if err != nil {
		return "", fmt.Errorf("探测出口 IP 失败：%w；请用 -announce-url 显式给出对外可达的 MCP 地址（有隧道时给隧道域名，如 https://<id>.trycloudflare.com/mcp）", err)
	}
	port := a.listenPort()
	if port == "" {
		return "", errors.New("-addr 里没有端口，拼不出对外地址；请用 -announce-url 指定")
	}
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]" // IPv6 字面量在 URL 里必须加方括号
	}
	return fmt.Sprintf("http://%s:%s/mcp", ip, port), nil
}

// egressIP 探测本机出网 IP（不经代理）。唯一用途是缺省拼对外地址。
func (a *announcer) egressIP(ctx context.Context) (string, error) {
	var lastErr error
	for _, url := range egressIPProbeURLs {
		probeCtx, cancel := context.WithTimeout(ctx, announceProbeTimeout)
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		resp, err := a.client.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("%s: %w", url, err)
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = fmt.Errorf("%s: %w", url, readErr)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s 返回 %s", url, resp.Status)
			continue
		}
		ip := strings.TrimSpace(string(raw))
		if net.ParseIP(ip) == nil {
			lastErr = fmt.Errorf("%s 返回的不是 IP: %q", url, ip)
			continue
		}
		return ip, nil
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的探测服务")
	}
	return "", lastErr
}

// listenPort 从 -addr 里取端口（对外地址默认为 http://<出口IP>:<端口>/mcp）。
func (a *announcer) listenPort() string {
	_, port, err := net.SplitHostPort(a.listenAddr)
	if err != nil {
		return ""
	}
	return port
}

// sanitizeNodeName 把主机名收敛成节点名允许的字符集（[a-z0-9-]）：小写、非法字符变
// 连字符、折叠连续的连字符、去掉首尾连字符。
func sanitizeNodeName(raw string) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		case r == '-':
			if !lastDash && b.Len() > 0 {
				b.WriteRune('-')
				lastDash = true
			}
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	return out
}

// splitCommaList 拆分逗号分隔的参数（-announce-labels recon,ad）：去空白、去重。
// 控制端也会归一化一遍，这里做只是别把重复标签写进日志与审计。
func splitCommaList(raw string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			if _, dup := seen[item]; dup {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

func truncateBody(raw []byte) string {
	body := strings.TrimSpace(string(raw))
	if len(body) > 300 {
		body = body[:300] + "…"
	}
	if body == "" {
		body = "（空响应体）"
	}
	return body
}
