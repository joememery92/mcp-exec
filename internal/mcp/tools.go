package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version 由构建脚本注入（与平台版本对齐）。
var Version = "dev"

const (
	maxOutputBytes = 256 << 10 // 同步输出上限：头尾各留一半，中间截断
	maxJobRead     = 1 << 20
	defaultSyncSec = 120
)

var workspaceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// Workspace 把一个工作区名解析成目录，并确保它落在 Root 之下。
// 工作区名只允许 [A-Za-z0-9._-]，因此不存在 "../" 这类穿越；这里再校验一次前缀，
// 防止日后有人放宽正则。
func (s *Sandbox) workspace(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("缺少参数 workspace")
	}
	if !workspaceNameRe.MatchString(name) {
		return "", fmt.Errorf("工作区名非法（只允许字母数字与 . _ -）: %q", name)
	}
	dir := filepath.Join(s.Root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建工作区失败: %w", err)
	}
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("工作区越界: %s", abs)
	}
	return abs, nil
}

// resolveInWorkspace 把工具里的相对路径限制在工作区内。绝对路径同样被拒绝，
// 因为执行端不该读宿主机的任意文件——那些内容本机才有权威副本。
func resolveInWorkspace(ws, rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return ws, nil
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "~") {
		return "", fmt.Errorf("只允许工作区内的相对路径: %q", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("路径越界: %q", rel)
	}
	return filepath.Join(ws, clean), nil
}

func (s *Sandbox) commandEnv(ws string) []string {
	env := os.Environ()
	drop := map[string]bool{
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true,
		"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NO_PROXY": true, "no_proxy": true,
		// ENV / BASH_ENV 会让每个新 shell 都去 source 一个文件——既能静默执行任意代码，
		// 也能像 resin-proxy 那样把 dash 直接搞崩。执行端不接受这类注入。
		"ENV": true, "BASH_ENV": true, "PROMPT_COMMAND": true, "CDPATH": true,
		// 调用令牌只用于 MCP 鉴权，不带进子进程（否则一次 env 就能打出来）。
		"MCPNODE_TOKEN": true,
	}
	out := make([]string, 0, len(env)+10)
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 && drop[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	if s.Proxy != "" {
		out = append(out, "HTTP_PROXY="+s.Proxy, "HTTPS_PROXY="+s.Proxy, "ALL_PROXY="+s.Proxy,
			"http_proxy="+s.Proxy, "https_proxy="+s.Proxy, "all_proxy="+s.Proxy)
	}
	if s.CACert != "" {
		if _, err := os.Stat(s.CACert); err == nil {
			out = append(out, "SSL_CERT_FILE="+s.CACert)
		}
	}
	out = append(out, "NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1",
		"MCPNODE_WORKSPACE="+ws, "MCPNODE_NODE=1",
	)
	// HOME 必须显式给出且不能为空：systemd 默认不注入 HOME，而 ProjectDiscovery 系列
	// 工具在 HOME 为空时会把模板/配置/缓存目录建到**当前目录**（也就是工作区）——
	// 既找不到 /root/nuclei-templates 里的模板（"no templates provided for scan"），
	// 又把 .nuclei-cache/.uncover-config 这类垃圾混进要回传的产物。
	if s.Home != "" {
		out = append(out, "HOME="+s.Home)
	}
	// 非登录 shell 不会读 /etc/profile，PATH 必须自己保证有值。
	if os.Getenv("PATH") == "" {
		out = append(out, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	return out
}

func clampSeconds(args map[string]any, key string, def int, max int) int {
	secs, ok := numericArg(args[key])
	if !ok || secs <= 0 {
		secs = def
	}
	if max > 0 && secs > max {
		secs = max
	}
	return secs
}

// numericArg 同时接受 JSON 解出来的 float64 与程序化调用传的 int/int64/字符串，
// 免得"参数写了没生效"这种只在 Go 侧出现、线上（HTTP JSON）却正常的错觉。
func numericArg(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case float32:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func truncateMiddle(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	half := limit / 2
	return s[:half] + fmt.Sprintf("\n…[中间省略 %d 字节]…\n", len(s)-2*half) + s[len(s)-half:]
}

// bashTool 是同步执行入口：短命令、探活、抓取用。长任务交给 bash_async。
func (s *Sandbox) bashTool() *Tool {
	return &Tool{
		Name: "bash",
		Description: "在工作区内同步执行 shell 命令（非登录 sh -c），返回 stdout/stderr 与退出码。" +
			"默认超时 120 秒，上限 300 秒；超过上限的长任务请用 bash_async，" +
			"需要常驻交互会话（REPL/psql/登录）请用 shell。" +
			"一次跑多条用 commands=[...]（同一 shell 内顺序执行，timeout_sec 是整批的总预算）。" +
			"HTTP(S) 流量已注入录制代理，会自动回到平台流量库。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command":     map[string]any{"type": "string", "description": "要执行的命令（与 commands 二选一；同时给出时以 commands 为准）"},
				"commands":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "按顺序在同一个 shell 里执行的命令列表，每条命令前打印一行「$ 命令」作分隔（不隐式加 set -e，前一条失败不影响后一条）"},
				"workspace":   map[string]any{"type": "string", "description": "工作区名（同一意图复用同名工作区）"},
				"timeout_sec": map[string]any{"type": "number", "description": "超时秒数，默认 120，上限 300；commands 模式下是整批命令的总预算"},
			},
			"required": []string{"workspace"},
		},
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			commands, hasCommands, err := argStringArray(args, "commands")
			if err != nil {
				return "", err
			}
			timeout := time.Duration(clampSeconds(args, "timeout_sec", defaultSyncSec, int(s.MaxSync.Seconds()))) * time.Second
			if hasCommands {
				if len(commands) == 0 {
					return "", fmt.Errorf("commands 是空数组：至少给一条命令，或改用 command")
				}
				if err := validateCommands(commands); err != nil {
					return "", err
				}
				// 头行一行内联展示这批命令；逐条的分隔行属于正文（commandScript 负责）。
				return s.runSyncNote(ctx, ws, commandScript(commands),
					"$ "+strings.Join(commands, " ; "), fmt.Sprintf(", %d 条命令", len(commands)), timeout)
			}
			command := strings.TrimSpace(argString(args, "command"))
			if command == "" {
				return "", fmt.Errorf("command 不能为空（多条命令用 commands=[...]）")
			}
			return s.runSync(ctx, ws, command, timeout)
		},
	}
}

// runSync 是同步执行的默认入口：头行就是命令本身。
func (s *Sandbox) runSync(ctx context.Context, ws, command string, timeout time.Duration) (string, error) {
	return s.runSyncNote(ctx, ws, command, "$ "+command, "", timeout)
}

// runSyncNote 与 runSync 相同，只是头行与状态行后缀由调用方给：commands 模式下要展示
// 用户写的那几条命令，而不是为了分隔输出拼出来的那段脚本本身。
func (s *Sandbox) runSyncNote(ctx context.Context, ws, command, label, note string, timeout time.Duration) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := shellCommand(runCtx, command)
	cmd.Dir = ws
	cmd.Env = s.commandEnv(ws)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start).Seconds()

	status := "退出码 0"
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		status = fmt.Sprintf("超时被杀（%s）", timeout)
	case err != nil:
		status = "执行失败: " + err.Error()
	}
	head := fmt.Sprintf("%s\n(%s, 耗时 %.1fs%s)\n", label, status, elapsed, note)
	return head + truncateMiddle(buf.String(), maxOutputBytes), nil
}

// ---------------- 后台任务 ----------------

type jobState struct {
	ID        string    `json:"id"`
	Workspace string    `json:"workspace"`
	Command   string    `json:"command"`
	LogPath   string    `json:"log_path"`
	State     string    `json:"state"` // running | done | failed | killed | timeout
	ExitCode  int       `json:"exit_code"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Deadline  time.Time `json:"deadline"`

	cancel context.CancelFunc
	done   chan struct{}
}

type jobManager struct {
	mu   sync.Mutex
	jobs map[string]*jobState
	// jobs 是沙箱里唯一驻留的状态：进程崩溃即丢，工作区文件仍在，重跑即可。
}

func newJobManager() *jobManager { return &jobManager{jobs: map[string]*jobState{}} }

func (m *jobManager) add(j *jobState) {
	m.mu.Lock()
	m.jobs[j.ID] = j
	m.mu.Unlock()
}

func (m *jobManager) get(id string) *jobState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs[id]
}

func (m *jobManager) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, j := range m.jobs {
		if j.State == "running" {
			n++
		}
	}
	return n
}

func (s *Sandbox) bashAsyncTool() *Tool {
	return &Tool{
		Name: "bash_async",
		Description: "在工作区后台执行长任务（全端口扫描、目录爆破、nuclei 全量），立刻返回 job id；" +
			"用 job_status / job_read 查看进度，job_kill 终止。输出写到 工作区/.jobs/<id>.log。" +
			"默认上限 30 分钟，超时按进程组终止。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command":     map[string]any{"type": "string", "description": "要执行的命令"},
				"workspace":   map[string]any{"type": "string", "description": "工作区名"},
				"timeout_sec": map[string]any{"type": "number", "description": "超时秒数，默认 1800"},
			},
			"required": []string{"command", "workspace"},
		},
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			command := strings.TrimSpace(argString(args, "command"))
			if command == "" {
				return "", fmt.Errorf("command 不能为空")
			}
			timeout := time.Duration(clampSeconds(args, "timeout_sec", int(s.MaxAsync.Seconds()), int(s.MaxAsync.Seconds()))) * time.Second
			return s.startAsync(ctx, ws, command, timeout)
		},
	}
}

func (s *Sandbox) startAsync(parent context.Context, ws, command string, timeout time.Duration) (string, error) {
	jobDir := filepath.Join(ws, ".jobs")
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 job 目录失败: %w", err)
	}
	id := randomID()
	logPath := filepath.Join(jobDir, id+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return "", fmt.Errorf("创建日志失败: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout) // 有意脱离请求上下文：调用方断开不该杀掉任务
	cmd := shellCommand(ctx, command)
	cmd.Dir = ws
	cmd.Env = s.commandEnv(ws)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		cancel()
		logFile.Close()
		return "", fmt.Errorf("启动失败: %w", err)
	}

	j := &jobState{
		ID: id, Workspace: filepath.Base(ws), Command: command, LogPath: logPath,
		State: "running", StartedAt: time.Now(), Deadline: time.Now().Add(timeout),
		cancel: cancel, done: make(chan struct{}),
	}
	s.jobs.add(j)

	go func() {
		waitErr := cmd.Wait()
		logFile.Close()
		j.EndedAt = time.Now()
		switch {
		case ctx.Err() == context.DeadlineExceeded:
			j.State = "timeout"
		case waitErr != nil:
			if cmd.ProcessState != nil {
				j.ExitCode = cmd.ProcessState.ExitCode()
			}
			if j.ExitCode < 0 {
				j.State = "killed"
			} else {
				j.State = "failed"
			}
		default:
			j.State = "done"
		}
		cancel()
		close(j.done)
	}()

	return fmt.Sprintf("job %s 已启动\n工作区: %s\n日志: %s\n上限: %s", id, filepath.Base(ws), logPath, timeout), nil
}

func (s *Sandbox) jobStatusTool() *Tool {
	return &Tool{
		Name:        "job_status",
		Description: "查看后台任务状态：running / done / failed / killed / timeout、退出码、已运行时间、日志大小。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"job_id": map[string]any{"type": "string"}},
			"required":   []string{"job_id"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			j := s.jobs.get(argString(args, "job_id"))
			if j == nil {
				return "", fmt.Errorf("未知 job: %s", argString(args, "job_id"))
			}
			size := int64(0)
			if fi, err := os.Stat(j.LogPath); err == nil {
				size = fi.Size()
			}
			elapsed := time.Since(j.StartedAt)
			if !j.EndedAt.IsZero() {
				elapsed = j.EndedAt.Sub(j.StartedAt)
			}
			return fmt.Sprintf("job %s\n状态: %s\n退出码: %d\n耗时: %.1fs\n日志: %s (%d 字节)\n命令: %s",
				j.ID, j.State, j.ExitCode, elapsed.Seconds(), j.LogPath, size, j.Command), nil
		},
	}
}

func (s *Sandbox) jobReadTool() *Tool {
	return &Tool{
		Name:        "job_read",
		Description: "读取后台任务日志的尾部（默认 64KB）——扫描类任务只需要看最后几百行与统计行。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"job_id": map[string]any{"type": "string"},
				"bytes":  map[string]any{"type": "number", "description": "读取尾部字节数，默认 65536，上限 1MB"},
			},
			"required": []string{"job_id"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			j := s.jobs.get(argString(args, "job_id"))
			if j == nil {
				return "", fmt.Errorf("未知 job: %s", argString(args, "job_id"))
			}
			n := clampInt(args, "bytes", 65536, maxJobRead)
			data, err := tailFile(j.LogPath, n)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("job %s [%s] 尾部 %d 字节：\n%s", j.ID, j.State, len(data), string(data)), nil
		},
	}
}

func (s *Sandbox) jobKillTool() *Tool {
	return &Tool{
		Name:        "job_kill",
		Description: "终止后台任务（连同其子进程组）。产出日志保留。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"job_id": map[string]any{"type": "string"}},
			"required":   []string{"job_id"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			j := s.jobs.get(argString(args, "job_id"))
			if j == nil {
				return "", fmt.Errorf("未知 job: %s", argString(args, "job_id"))
			}
			if j.State != "running" {
				return fmt.Sprintf("job %s 已是 %s，无需终止", j.ID, j.State), nil
			}
			j.cancel()
			select {
			case <-j.done:
			case <-time.After(10 * time.Second):
			}
			return fmt.Sprintf("job %s 已终止（当前状态 %s）", j.ID, j.State), nil
		},
	}
}

func tailFile(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读取日志失败: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if int64(n) > size {
		n = int(size)
	}
	if _, err := f.Seek(size-int64(n), io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:read], nil
}

func argString(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// argStringArray 取一个字符串数组参数：既接受 JSON 解出来的 []any，也接受程序化调用传的
// []string——与 numericArg 同理，免得"参数写了没生效"这种错觉只在 Go 侧出现、线上（HTTP）却正常。
func argStringArray(args map[string]any, key string) ([]string, bool, error) {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil, false, nil
	}
	switch t := raw.(type) {
	case []string:
		return append([]string(nil), t...), true, nil
	case []any:
		out := make([]string, 0, len(t))
		for i, v := range t {
			s, ok := v.(string)
			if !ok {
				return nil, true, fmt.Errorf("%s[%d] 不是字符串", key, i)
			}
			out = append(out, s)
		}
		return out, true, nil
	default:
		return nil, true, fmt.Errorf("%s 需要字符串数组（单条命令请用 command）", key)
	}
}

// validateCommands 拒绝空命令：一条空命令会让"分隔行"与"实际执行"错位，
// 看起来跑了其实什么都没跑。
func validateCommands(commands []string) error {
	for i, c := range commands {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("commands[%d] 为空", i)
		}
	}
	return nil
}

// commandScript 把多条命令拼成一段脚本：每条命令前插一行显示「$ 命令」作分隔，命令本身原样跟随。
//
// 分隔行用 printf + 单引号原样引用，而不是 echo "$ 命令"：命令里出现的 "、$、反引号或反斜杠
// 会被双引号展开解释掉（POSIX 的 echo 还会解释反斜杠），分隔行就与实际执行的命令对不上。
func commandScript(commands []string) string {
	var b strings.Builder
	for _, c := range commands {
		fmt.Fprintf(&b, "printf '%%s\\n' %s\n", shellQuote("$ "+c))
		b.WriteString(c)
		b.WriteString("\n")
	}
	return b.String()
}

// workspacesTool 让控制端能做两件事：看清沙箱里有哪些工作区、以及按证据回收它们。
// 回收的判断（哪些可以删）不在这里做——沙箱只知道文件，不知道"产物是否已回传"。
func (s *Sandbox) workspacesTool() *Tool {
	return &Tool{
		Name: "workspaces",
		Description: "工作区管理：action=list 列出全部工作区（文件数/字节数/最后修改时间）；" +
			"action=remove 删除一个工作区（需要 workspace）。删除不可逆，控制端必须先确认产物已回传并校验。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":    map[string]any{"type": "string", "enum": []string{"list", "remove"}},
				"workspace": map[string]any{"type": "string", "description": "action=remove 时必填"},
			},
			"required": []string{"action"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			switch strings.TrimSpace(argString(args, "action")) {
			case "list":
				entries, err := os.ReadDir(s.Root)
				if err != nil {
					return "", fmt.Errorf("读取工作区根失败: %w", err)
				}
				rows := make([]map[string]any, 0, len(entries))
				var total int64
				for _, e := range entries {
					if !e.IsDir() {
						continue
					}
					dir := filepath.Join(s.Root, e.Name())
					files, bytes, newest := countTree(dir)
					total += bytes
					rows = append(rows, map[string]any{
						"name": e.Name(), "files": files, "bytes": bytes,
						"modified": newest.UTC().Format(time.RFC3339),
					})
				}
				b, err := json.Marshal(map[string]any{
					"root": s.Root, "count": len(rows), "total_bytes": total, "workspaces": rows,
				})
				if err != nil {
					return "", err
				}
				return string(b), nil
			case "remove":
				name := strings.TrimSpace(argString(args, "workspace"))
				ws, err := s.workspace(name)
				if err != nil {
					return "", err
				}
				// workspace() 会用 filepath.Join + Abs 拼路径；这里再确认最后一段就是请求的名字，
				// 避免任何形式的路径拼接滑出目标目录。
				if filepath.Base(ws) != name {
					return "", fmt.Errorf("工作区名不匹配")
				}
				files, bytes, _ := countTree(ws)
				if err := os.RemoveAll(ws); err != nil {
					return "", fmt.Errorf("删除失败: %w", err)
				}
				return fmt.Sprintf("已删除工作区 %s（%d 个文件，%d 字节）", name, files, bytes), nil
			default:
				return "", fmt.Errorf("不支持的 action: %s（只支持 list/remove）", argString(args, "action"))
			}
		},
	}
}

// countTree 统计目录下的文件数与总字节数，并返回最新的修改时间。
//
// 空目录（意图跑完但没写出任何文件）没有文件可看 mtime，此时回落到目录自身的
// 修改时间——否则调用方会拿到零值时间（0001-01-01），把"刚建的空气工作区"
// 误判成"很久以前"，GC 的保留期形同虚设。
func countTree(dir string) (files int, bytes int64, newest time.Time) {
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		files++
		bytes += info.Size()
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	if newest.IsZero() {
		if info, err := os.Stat(dir); err == nil {
			newest = info.ModTime()
		}
	}
	return files, bytes, newest
}
