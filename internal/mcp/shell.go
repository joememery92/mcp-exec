package mcp

import (
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// 会话面：给"需要多步交互"的场景（REPL、数据库客户端、登录会话、msfconsole）
// 一个常驻进程。一次 open 之后可以 send/read 很多轮，进程活在工作区目录里。
//
// 与 job 的区别：job 是"跑完就结束、输出落文件"，会话是"活着、需要来回说话"。
// 会话同样是可丢的驻留状态——节点重启就没了，调用方重新 open 即可，事实不在这里。
//
// 输出缓冲有上限（shellSessionBuf）。无上限的缓冲等于把节点的内存交给一条 `yes`
// 或一个死循环打印的命令，那才是真的丢数据；超出上限只丢**最旧**的字节，并把丢弃量
// 如实带进 read 结果，调用方因此能分辨"没有输出"与"输出被截断"。
const (
	shellDefaultCommand = "/bin/bash"
	shellSessionMax     = 8
	shellSessionIdle    = 30 * time.Minute
	shellSessionBuf     = 4 << 20
	shellSessionReadMax = 1 << 20
	shellWaitDefaultMS  = 500
	shellWaitMaxMS      = 10000
	shellCloseGrace     = 2 * time.Second
)

// shellSnapshot 是会话状态的一次快照。
type shellSnapshot struct {
	exited   bool
	exitCode int
	closed   bool
	pending  int   // 缓冲里还没被 read 取走的字节
	dropped  int64 // 因缓冲上限被丢弃的旧字节累计
}

type shellSession struct {
	id        string
	name      string
	workspace string
	command   string
	pid       int
	bufLimit  int

	cmd   *exec.Cmd // 构造后只读
	stdin io.WriteCloser
	done  chan struct{} // 进程退出或会话被回收后关闭

	notify chan struct{} // cap 1：有新输出或状态变化时投递

	// mu 保护 buf/dropped/exited/exitCode/closed/lastUsed。
	// 加锁顺序固定：shellManager.mu 在外、shellSession.mu 在内，绝不反过来。
	mu       sync.Mutex
	buf      []byte
	dropped  int64
	exited   bool
	exitCode int
	closed   bool
	lastUsed time.Time
}

// Write 是 cmd.Stdout/Stderr 的落点（因此必须导出：exec 只接受 io.Writer）：
// 追加进缓冲并唤醒等待中的 read。
func (ss *shellSession) Write(p []byte) (int, error) {
	ss.mu.Lock()
	ss.buf = append(ss.buf, p...)
	if over := len(ss.buf) - ss.bufLimit; over > 0 {
		n := copy(ss.buf, ss.buf[over:]) // 丢最旧的，留最新的
		ss.buf = ss.buf[:n]
		ss.dropped += int64(over)
	}
	ss.mu.Unlock()
	ss.signal()
	return len(p), nil
}

func (ss *shellSession) signal() {
	select {
	case ss.notify <- struct{}{}:
	default: // 已有待处理的唤醒信号：read 回到循环时会看到缓冲
	}
}

func (ss *shellSession) touch() {
	ss.mu.Lock()
	ss.lastUsed = time.Now()
	ss.mu.Unlock()
}

func (ss *shellSession) idleFor(now time.Time) time.Duration {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return now.Sub(ss.lastUsed)
}

func (ss *shellSession) snapshot() shellSnapshot {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return shellSnapshot{
		exited: ss.exited, exitCode: ss.exitCode, closed: ss.closed,
		pending: len(ss.buf), dropped: ss.dropped,
	}
}

// take 取走至多 n 字节的**新**输出：取走的字节不会再返回给下次 read。
func (ss *shellSession) take(n int) []byte {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if n <= 0 || len(ss.buf) == 0 {
		return nil
	}
	if n > len(ss.buf) {
		n = len(ss.buf)
	}
	data := make([]byte, n)
	copy(data, ss.buf[:n])
	if n == len(ss.buf) {
		ss.buf = nil // 取空就放掉底层数组
	} else {
		ss.buf = ss.buf[n:]
		ss.signal() // 还有积压：唤醒其它等待中的 read，别让它们白等到超时
	}
	return data
}

// readOutput 取回新输出。缓冲里没有数据时最多等 wait；等到就返回，等不到返回空。
// 进程已退出或会话已关闭时不再空等——否则调用方要为一个死会话白等满 wait。
func (ss *shellSession) readOutput(ctx context.Context, wait time.Duration, n int) ([]byte, shellSnapshot) {
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if data := ss.take(n); len(data) > 0 {
			return data, ss.snapshot()
		}
		snap := ss.snapshot()
		if snap.exited || snap.closed {
			return nil, snap
		}
		select {
		case <-ss.notify:
			// 有新输出或状态变化：回到循环再取一次
		case <-timer.C:
			return nil, ss.snapshot()
		case <-ctx.Done():
			return nil, ss.snapshot()
		}
	}
}

// send 把 text 写进会话 stdin。
func (ss *shellSession) send(text string) error {
	snap := ss.snapshot()
	switch {
	case snap.closed:
		return fmt.Errorf("会话 %s 已关闭，无法写入", ss.id)
	case snap.exited:
		return fmt.Errorf("会话 %s 的进程已退出（退出码 %d），无法再写入；请 action=close 回收后重新 open，或改用 bash",
			ss.id, snap.exitCode)
	}
	if _, err := io.WriteString(ss.stdin, text); err != nil {
		// 写入撞上并发 close/进程退出时，报"会话已结束"比底层管道错误（file already closed）
		// 更有用：调用方看到的是会话状态，而不是 os.File 的实现细节。
		if snap := ss.snapshot(); snap.closed || snap.exited {
			return fmt.Errorf("会话 %s 已结束（%s）: %w", ss.id, stateText(snap), err)
		}
		return fmt.Errorf("写入会话 %s 失败: %w", ss.id, err)
	}
	return nil
}

// exit 由 Wait 的 goroutine 调用，记录进程终结。
func (ss *shellSession) exit(code int) {
	ss.mu.Lock()
	ss.exited = true
	ss.exitCode = code
	ss.mu.Unlock()
	ss.signal()
	close(ss.done)
}

// shutdown 终止会话并回收缓冲：先关 stdin 让 shell 自己收场（EOF 会让非交互 shell
// 退出），宽限期内没死再杀整个进程组；被回收的会话一律视为已关闭。
func (ss *shellSession) shutdown() {
	ss.mu.Lock()
	already := ss.closed
	ss.closed = true
	ss.mu.Unlock()
	ss.signal()
	if already {
		return
	}
	if ss.stdin != nil {
		_ = ss.stdin.Close()
	}
	select {
	case <-ss.done:
	case <-time.After(shellCloseGrace):
		killSessionGroup(ss.cmd) // shell 的前台子进程在跑（如 sleep）：整组杀掉
		select {
		case <-ss.done:
		case <-time.After(shellCloseGrace):
		}
	}
	ss.mu.Lock()
	ss.buf = nil
	ss.mu.Unlock()
}

// stateText 把快照渲染成人看的状态。
func stateText(snap shellSnapshot) string {
	switch {
	case snap.closed:
		return "closed"
	case snap.exited:
		return fmt.Sprintf("exited(退出码 %d)", snap.exitCode)
	default:
		return "running"
	}
}

// ---------------- 会话表 ----------------

// shellManager 持有一组常驻会话。上限与空闲回收都是节点级策略：控制端可能已经忘了
// 某个会话，节点不能陪着一起忘。
type shellManager struct {
	mu       sync.Mutex
	sessions map[string]*shellSession
	max      int
	idle     time.Duration
	bufLimit int
}

func newShellManager() *shellManager {
	return &shellManager{
		sessions: map[string]*shellSession{},
		max:      shellSessionMax,
		idle:     shellSessionIdle,
		bufLimit: shellSessionBuf,
	}
}

func (m *shellManager) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// open 起一个常驻会话：独立进程组、cwd=工作区、环境与 bash 工具一致。
// 上限检查、id 分配与进程启动都在锁内完成——否则两个并发 open 会一起挤进上限。
func (m *shellManager) open(sb *Sandbox, ws, command, name string) (*shellSession, error) {
	m.sweep() // 先回收空闲会话，别让"忘了 close 的旧会话"顶掉上限
	command = strings.TrimSpace(command)
	if command == "" {
		command = shellDefaultCommand
	}
	if name = strings.TrimSpace(name); name == "" {
		name = "auto"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= m.max {
		return nil, fmt.Errorf("会话数已达上限 %d（现有 %s）：先 shell action=close 回收不用的会话",
			m.max, m.idsLocked())
	}
	ss := &shellSession{
		id: randomID(), name: name, workspace: ws, command: command, bufLimit: m.bufLimit,
		done: make(chan struct{}), notify: make(chan struct{}, 1),
	}
	ss.touch()
	cmd, stdin, err := startSessionCmd(command, ws, sb.commandEnv(ws), ss)
	if err != nil {
		return nil, fmt.Errorf("启动会话失败（%s）: %w", command, err)
	}
	ss.cmd = cmd
	ss.stdin = stdin
	ss.pid = cmd.Process.Pid
	m.sessions[ss.id] = ss
	go func() {
		_ = cmd.Wait()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		ss.exit(code)
	}()
	return ss, nil
}

// sweep 回收空闲超时的会话。挑人（持锁）与杀进程（不持锁，最多等两个宽限期）分开：
// 混在一起会让一次回收把所有并发调用都堵住。
func (m *shellManager) sweep() {
	now := time.Now()
	var dead []*shellSession
	m.mu.Lock()
	for id, ss := range m.sessions {
		if ss.idleFor(now) >= m.idle {
			dead = append(dead, ss)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()
	for _, ss := range dead {
		log.Printf("[mcpnode] 会话 %s 空闲超过 %s 被回收（工作区 %s）", ss.id, m.idle, ss.workspace)
		ss.shutdown()
	}
}

// get 取会话并刷新空闲计时；未知（或已被回收）时给出可行动的报错。
func (m *shellManager) get(id string) (*shellSession, error) {
	m.sweep()
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("缺少参数 session_id")
	}
	m.mu.Lock()
	ss := m.sessions[id]
	m.mu.Unlock()
	if ss == nil {
		return nil, fmt.Errorf("未知会话 %q（可能已 close 或被空闲回收）：用 action=list 看现有会话", id)
	}
	ss.touch()
	return ss, nil
}

// close 摘掉会话并终止其进程组。
func (m *shellManager) close(id string) (*shellSession, error) {
	m.sweep()
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("缺少参数 session_id")
	}
	m.mu.Lock()
	ss := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if ss == nil {
		return nil, fmt.Errorf("未知会话 %q（可能已经 close 过）：用 action=list 看现有会话", id)
	}
	ss.shutdown()
	return ss, nil
}

// list 按 id 排序返回会话：输出稳定，便于控制端 diff。
func (m *shellManager) list() []*shellSession {
	m.sweep()
	m.mu.Lock()
	out := make([]*shellSession, 0, len(m.sessions))
	for _, ss := range m.sessions {
		out = append(out, ss)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func (m *shellManager) idsLocked() string {
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// ---------------- 工具 ----------------

// shellTool 是常驻交互式会话。参数风格与 workspaces 一致：一个 action 带全部可选参数。
func (s *Sandbox) shellTool() *Tool {
	return &Tool{
		Name: "shell",
		Description: fmt.Sprintf(
			"常驻交互式会话（REPL、数据库客户端、登录会话等多步交互；一次跑一条或几条命令仍用 bash）：\n"+
				"- action=open：在工作区里起一个常驻会话（默认 %s，可用 command 指定），返回 session_id\n"+
				"- action=send：把 text 写进会话 stdin（默认自动补换行；newline=false 可发不带换行的按键/控制字符）\n"+
				"- action=read：取回自上次 read 以来的新输出；wait_ms 内没有输出就返回空（不是错误）\n"+
				"- action=list：列出全部会话；action=close：终止会话（连子进程组一起）\n"+
				"会话上限 %d 个、空闲 %s 自动回收；会话不绑定单次请求，控制端断开也会继续活着。",
			shellDefaultCommand, s.shells.max, s.shells.idle),
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":     map[string]any{"type": "string", "enum": []string{"open", "send", "read", "list", "close"}},
				"workspace":  map[string]any{"type": "string", "description": "action=open 必填：会话的工作目录（工作区名）"},
				"command":    map[string]any{"type": "string", "description": "action=open：要常驻的命令，默认 /bin/bash（如 psql、msfconsole、python3）"},
				"name":       map[string]any{"type": "string", "description": "action=open：会话备注名，默认 auto"},
				"session_id": map[string]any{"type": "string", "description": "action=send/read/close 必填"},
				"text":       map[string]any{"type": "string", "description": "action=send：写入会话的内容（为空且 newline=true 等同于按一次回车）"},
				"newline":    map[string]any{"type": "boolean", "description": "action=send：是否在 text 后补换行，默认 true"},
				"wait_ms":    map[string]any{"type": "number", "description": fmt.Sprintf("action=read：没有新输出时最多等多少毫秒，默认 %d，上限 %d", shellWaitDefaultMS, shellWaitMaxMS)},
				"bytes":      map[string]any{"type": "number", "description": fmt.Sprintf("action=read：本次最多取回多少字节，默认 32768，上限 %d", shellSessionReadMax)},
			},
			"required": []string{"action"},
		},
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			switch action := strings.ToLower(strings.TrimSpace(argString(args, "action"))); action {
			case "open":
				return s.shellOpen(args)
			case "send":
				return s.shellSend(args)
			case "read":
				return s.shellRead(ctx, args)
			case "list":
				return s.shellList()
			case "close":
				return s.shellClose(args)
			default:
				return "", fmt.Errorf("不支持的 action: %q（只支持 open/send/read/list/close）", argString(args, "action"))
			}
		},
	}
}

func (s *Sandbox) shellOpen(args map[string]any) (string, error) {
	ws, err := s.workspace(argString(args, "workspace"))
	if err != nil {
		return "", err
	}
	ss, err := s.shells.open(s, ws, argString(args, "command"), argString(args, "name"))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("已开启会话 %s\n名称: %s\n命令: %s\n工作区: %s\nPID: %d\n现有会话: %d/%d（空闲 %s 回收，用完请 action=close）\n下一步: shell action=send session_id=%s text=\"...\"，然后 action=read 取输出。",
		ss.id, ss.name, ss.command, ss.workspace, ss.pid, s.shells.count(), s.shells.max, s.shells.idle, ss.id), nil
}

func (s *Sandbox) shellSend(args map[string]any) (string, error) {
	ss, err := s.shells.get(argString(args, "session_id"))
	if err != nil {
		return "", err
	}
	text := argString(args, "text")
	newline := true
	if v, ok := args["newline"].(bool); ok {
		newline = v
	}
	if newline {
		text += "\n"
	} else if text == "" {
		return "", fmt.Errorf("text 为空且 newline=false：没有任何内容可写（要按回车就传空 text 且 newline=true）")
	}
	if err := ss.send(text); err != nil {
		return "", err
	}
	return fmt.Sprintf("已写入会话 %s %d 字节（补换行=%t）；用 action=read 取回新输出。", ss.id, len(text), newline), nil
}

func (s *Sandbox) shellRead(ctx context.Context, args map[string]any) (string, error) {
	ss, err := s.shells.get(argString(args, "session_id"))
	if err != nil {
		return "", err
	}
	wait := time.Duration(clampInt(args, "wait_ms", shellWaitDefaultMS, shellWaitMaxMS)) * time.Millisecond
	n := clampInt(args, "bytes", 32768, shellSessionReadMax)
	data, snap := ss.readOutput(ctx, wait, n)

	var b strings.Builder
	fmt.Fprintf(&b, "session %s (%s) 状态=%s 本次 %d 字节 待读 %d 字节\n",
		ss.id, ss.name, stateText(snap), len(data), snap.pending)
	if snap.dropped > 0 {
		fmt.Fprintf(&b, "注意：输出缓冲超过上限，最早的 %d 字节已被丢弃（read 越及时越不容易丢）\n", snap.dropped)
	}
	b.WriteString("--- 输出 ---\n")
	b.Write(data)
	if len(data) == 0 {
		// 无新输出不是错误：调用方可以继续 send 或稍后再 read。
		fmt.Fprintf(&b, "（本次没有新输出，等满 %s；进程仍在时可稍后再 read）\n", wait)
	}
	return b.String(), nil
}

func (s *Sandbox) shellList() (string, error) {
	list := s.shells.list()
	if len(list) == 0 {
		return fmt.Sprintf("当前没有会话（上限 %d，空闲 %s 回收）", s.shells.max, s.shells.idle), nil
	}
	now := time.Now()
	var b strings.Builder
	fmt.Fprintf(&b, "会话 %d/%d（空闲 %s 回收）：\n", len(list), s.shells.max, s.shells.idle)
	for _, ss := range list {
		snap := ss.snapshot()
		fmt.Fprintf(&b, "%s  %-10s 状态=%-16s 空闲=%s 待读=%d 字节 丢弃=%d 字节 工作区=%s 命令=%s\n",
			ss.id, ss.name, stateText(snap), ss.idleFor(now).Truncate(time.Second),
			snap.pending, snap.dropped, ss.workspace, ss.command)
	}
	return b.String(), nil
}

func (s *Sandbox) shellClose(args map[string]any) (string, error) {
	ss, err := s.shells.close(argString(args, "session_id"))
	if err != nil {
		return "", err
	}
	snap := ss.snapshot()
	return fmt.Sprintf("已关闭会话 %s（%s，进程组已终止；回收 %d 字节未读输出）", ss.id, ss.name, snap.pending), nil
}
