package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// 会话面（shell 工具）与 bash(commands=[...]) 的行为测试。
//
// 会话的语义都是"流"的：send 立刻返回、输出随后才到，因此所有断言都通过
// readUntil/drain 轮询到位，而不是 sleep 一个固定时长后赌一次 read。

// callTool 不碰 *testing.T，因此可以在 goroutine 里调用（并发用例需要）。
func callTool(sb *Sandbox, tool string, args map[string]any) (string, error) {
	impl, ok := sb.byName[tool]
	if !ok {
		return "", fmt.Errorf("工具不存在: %s", tool)
	}
	return impl.Call(context.Background(), args)
}

// sessionIDFrom 从 open 的返回里取 session_id：返回文本以「已开启会话 <id>」开头。
func sessionIDFrom(t *testing.T, out string) string {
	t.Helper()
	fields := strings.Fields(out)
	if len(fields) < 2 {
		t.Fatalf("open 返回异常: %s", out)
	}
	id := fields[1]
	if len(id) != 16 {
		t.Fatalf("session_id 不像短 hex: %q（原返回 %s）", id, out)
	}
	return id
}

func openShell(t *testing.T, sb *Sandbox, ws string) string {
	t.Helper()
	out, err := call(t, sb, "shell", map[string]any{"action": "open", "workspace": ws})
	if err != nil {
		t.Fatalf("open 失败: %v", err)
	}
	return sessionIDFrom(t, out)
}

func sendShell(t *testing.T, sb *Sandbox, id, text string) {
	t.Helper()
	if _, err := call(t, sb, "shell", map[string]any{"action": "send", "session_id": id, "text": text}); err != nil {
		t.Fatalf("send 失败: %v", err)
	}
}

// outputBody 从 read 的返回里取出纯输出：头行是会话状态，正文在「--- 输出 ---」之后。
func outputBody(out string) string {
	const marker = "--- 输出 ---\n"
	i := strings.Index(out, marker)
	if i < 0 {
		return ""
	}
	body := out[i+len(marker):]
	if strings.HasPrefix(body, "（本次没有新输出") {
		return ""
	}
	return body
}

// readUntil 反复 read 直到出现 want 或超时，返回累积到的完整输出。
func readUntil(t *testing.T, sb *Sandbox, id, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var b strings.Builder
	for time.Now().Before(deadline) {
		out, err := call(t, sb, "shell", map[string]any{
			"action": "read", "session_id": id, "wait_ms": 200, "bytes": 65536,
		})
		if err != nil {
			t.Fatalf("read 失败: %v", err)
		}
		b.WriteString(out)
		if strings.Contains(out, want) {
			return b.String()
		}
	}
	t.Fatalf("等待 %q 超时，已收到:\n%s", want, b.String())
	return ""
}

// drain 反复 read 直到「本次没有新输出」，用来把某条命令的输出流干净。
func drain(t *testing.T, sb *Sandbox, id string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var b strings.Builder
	for time.Now().Before(deadline) {
		out, err := call(t, sb, "shell", map[string]any{
			"action": "read", "session_id": id, "wait_ms": 150, "bytes": 65536,
		})
		if err != nil {
			t.Fatalf("read 失败: %v", err)
		}
		b.WriteString(out)
		if strings.Contains(out, "本次 0 字节") {
			return
		}
	}
	t.Fatalf("输出一直没流干:\n%s", b.String())
}

// toleratedShellErr 是并发收尾阶段允许的失败：会话被关掉之后，正在飞的 send/read
// 只会拿到这类可预期错误——它们是正常语义，不是竞态。
func toleratedShellErr(err error) bool {
	if err == nil {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "未知会话") || strings.Contains(s, "已关闭") ||
		strings.Contains(s, "无法再写入") || strings.Contains(s, "已结束")
}

func TestShellSessionRoundTrip(t *testing.T) {
	sb := newTestSandbox(t)
	id := openShell(t, sb, "sh1")

	sendShell(t, sb, id, "echo hello-shell")
	if out := readUntil(t, sb, id, "hello-shell", 5*time.Second); !strings.Contains(out, "hello-shell") {
		t.Fatalf("未读回命令输出:\n%s", out)
	}

	// 会话是常驻的：跨调用还是同一个进程、同一个工作目录。
	ws, err := sb.workspace("sh1")
	if err != nil {
		t.Fatal(err)
	}
	sendShell(t, sb, id, "pwd")
	if out := readUntil(t, sb, id, ws, 5*time.Second); !strings.Contains(out, ws) {
		t.Fatalf("会话工作目录应为工作区 %s:\n%s", ws, out)
	}

	// 没有新输出时：读回空输出但不是错误（drain 内部断言了「本次 0 字节」）。
	drain(t, sb, id, 5*time.Second)

	// 进程退出后状态可见，且不再空等、不再接受写入。
	sendShell(t, sb, id, "exit")
	out := readUntil(t, sb, id, "状态=exited", 5*time.Second)
	if !strings.Contains(out, "状态=exited") {
		t.Fatalf("退出后状态应为 exited:\n%s", out)
	}
	if _, err := call(t, sb, "shell", map[string]any{"action": "send", "session_id": id, "text": "echo x"}); err == nil {
		t.Fatal("已退出的会话应拒绝写入")
	}

	closed, err := call(t, sb, "shell", map[string]any{"action": "close", "session_id": id})
	if err != nil {
		t.Fatalf("close 失败: %v", err)
	}
	if !strings.Contains(closed, id) {
		t.Fatalf("close 返回异常: %s", closed)
	}
	if _, err := call(t, sb, "shell", map[string]any{"action": "close", "session_id": id}); err == nil {
		t.Fatal("重复 close 应报未知会话")
	}
	if n := sb.shells.count(); n != 0 {
		t.Fatalf("close 后会话应已回收，实际剩 %d", n)
	}
}

func TestShellSessionKeepsEveryByte(t *testing.T) {
	sb := newTestSandbox(t)
	id := openShell(t, sb, "sh2")

	// 连续两条命令：第一条的输出不能被后续 read 吃掉，第二条也不许丢。
	sendShell(t, sb, id, "echo first-line")
	readUntil(t, sb, id, "first-line", 5*time.Second)
	sendShell(t, sb, id, "echo second-line")
	if out := readUntil(t, sb, id, "second-line", 5*time.Second); !strings.Contains(out, "second-line") {
		t.Fatalf("第二条命令的输出丢了:\n%s", out)
	}

	// 分块读取（每次最多 4 字节）：拼起来必须与命令输出逐字节一致。
	drain(t, sb, id, 5*time.Second)
	sendShell(t, sb, id, "printf 'abcdefgh'")
	var got strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for got.Len() < len("abcdefgh") && time.Now().Before(deadline) {
		out, err := call(t, sb, "shell", map[string]any{
			"action": "read", "session_id": id, "wait_ms": 200, "bytes": 4,
		})
		if err != nil {
			t.Fatalf("read 失败: %v", err)
		}
		got.WriteString(outputBody(out))
	}
	if got.String() != "abcdefgh" {
		t.Fatalf("分块读取丢字节或串位: %q", got.String())
	}
}

func TestShellConcurrentReadWriteClose(t *testing.T) {
	sb := newTestSandbox(t)
	id := openShell(t, sb, "sh-con")
	if _, err := callTool(sb, "shell", map[string]any{
		"action": "send", "session_id": id, "text": "for i in $(seq 1 500); do echo line-$i; done",
	}); err != nil {
		t.Fatal(err)
	}

	// 读、写、列会话同时打；期间再插一次 close。判据只有两条：
	// 不 panic（进程活着跑完）且不出现"可预期错误"之外的错误。
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	report := func(err error) {
		if !toleratedShellErr(err) {
			errs <- err.Error()
		}
	}

	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 30 {
				_, err := callTool(sb, "shell", map[string]any{
					"action": "read", "session_id": id, "wait_ms": 5, "bytes": 128,
				})
				report(err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := range 30 {
			_, err := callTool(sb, "shell", map[string]any{
				"action": "send", "session_id": id, "text": fmt.Sprintf("echo concurrent-%d", j),
			})
			report(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 20 {
			_, err := callTool(sb, "shell", map[string]any{"action": "list"})
			report(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		_, err := callTool(sb, "shell", map[string]any{"action": "close", "session_id": id})
		report(err)
	}()

	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("并发调用出错: %s", e)
	}
	if n := sb.shells.count(); n != 0 {
		t.Fatalf("close 后不该还有会话，实际 %d", n)
	}
}

func TestShellSessionCapRequiresClose(t *testing.T) {
	sb := newTestSandbox(t)
	if sb.shells.max != shellSessionMax {
		t.Fatalf("默认会话上限应为 %d，实际 %d", shellSessionMax, sb.shells.max)
	}
	sb.shells.max = 2
	a := openShell(t, sb, "sh-cap")
	b := openShell(t, sb, "sh-cap")

	_, err := call(t, sb, "shell", map[string]any{"action": "open", "workspace": "sh-cap"})
	if err == nil {
		t.Fatal("超过上限应报错")
	}
	if !strings.Contains(err.Error(), "上限") || !strings.Contains(err.Error(), "close") {
		t.Fatalf("上限错误应提示先 close: %v", err)
	}
	if !strings.Contains(err.Error(), a) && !strings.Contains(err.Error(), b) {
		t.Fatalf("上限错误应列出现有会话 id，方便直接回收: %v", err)
	}

	if _, err := call(t, sb, "shell", map[string]any{"action": "close", "session_id": a}); err != nil {
		t.Fatal(err)
	}
	c := openShell(t, sb, "sh-cap") // 回收后应能再开一个
	if c == a || c == b {
		t.Fatalf("session_id 复用: %s", c)
	}
	list, err := call(t, sb, "shell", map[string]any{"action": "list"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list, b) || !strings.Contains(list, c) || strings.Contains(list, a) {
		t.Fatalf("list 与会话表不一致:\n%s", list)
	}
	for _, id := range []string{b, c} {
		if _, err := call(t, sb, "shell", map[string]any{"action": "close", "session_id": id}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestShellIdleTimeoutReapsSession(t *testing.T) {
	sb := newTestSandbox(t)
	sb.shells.idle = 300 * time.Millisecond
	id := openShell(t, sb, "sh-idle")

	sb.shells.mu.Lock()
	ss := sb.shells.sessions[id]
	sb.shells.mu.Unlock()
	if ss == nil {
		t.Fatal("会话不在表里")
	}

	sendShell(t, sb, id, "sleep 30") // 让 shell 的前台子进程活着
	time.Sleep(600 * time.Millisecond)

	// 会话没有被后续调用照看：任意一次调用都会先扫一遍空闲会话。
	if _, err := call(t, sb, "shell", map[string]any{"action": "read", "session_id": id}); err == nil {
		t.Fatal("空闲超时的会话应已被回收")
	}
	if n := sb.shells.count(); n != 0 {
		t.Fatalf("回收后表里不该有会话，实际 %d", n)
	}
	select {
	case <-ss.done:
	default:
		t.Fatal("回收必须终止会话进程（done 未关闭）")
	}

	// 活跃会话不被误回收：read 会刷新空闲计时。
	keep := openShell(t, sb, "sh-idle")
	for range 4 {
		if _, err := call(t, sb, "shell", map[string]any{"action": "read", "session_id": keep, "wait_ms": 50}); err != nil {
			t.Fatalf("活跃会话被误回收: %v", err)
		}
		time.Sleep(120 * time.Millisecond)
	}
	if _, err := call(t, sb, "shell", map[string]any{"action": "close", "session_id": keep}); err != nil {
		t.Fatal(err)
	}
}

func TestShellConfinesWorkspaceAndRejectsBadArgs(t *testing.T) {
	sb := newTestSandbox(t)
	for _, bad := range []string{"../escape", "/etc", "a/b", "..", ""} {
		if _, err := call(t, sb, "shell", map[string]any{"action": "open", "workspace": bad}); err == nil {
			t.Fatalf("工作区 %q 应被拒绝（会话目录必须走 workspace() 校验）", bad)
		}
	}
	id := openShell(t, sb, "sh-ws")
	ws, err := sb.workspace("sh-ws")
	if err != nil {
		t.Fatal(err)
	}
	sendShell(t, sb, id, "pwd")
	if out := readUntil(t, sb, id, ws, 5*time.Second); !strings.Contains(out, ws) {
		t.Fatalf("会话工作目录应为 %s:\n%s", ws, out)
	}

	// 起不来的命令要报错，而不是留一个死会话白占名额。
	_, err = call(t, sb, "shell", map[string]any{
		"action": "open", "workspace": "sh-ws", "command": "/nonexistent/not-a-shell",
	})
	if err == nil || !strings.Contains(err.Error(), "启动会话失败") {
		t.Fatalf("不存在的命令应报启动失败: %v", err)
	}
	if n := sb.shells.count(); n != 1 {
		t.Fatalf("启动失败的会话不该占用名额，实际 %d", n)
	}

	for _, args := range []map[string]any{
		{"action": "send"}, {"action": "read"}, {"action": "close"},
		{"action": "send", "session_id": "ffffffffffffffff"},
		{"action": "nope"},
	} {
		if _, err := call(t, sb, "shell", args); err == nil {
			t.Fatalf("该报错: %v", args)
		}
	}

	if _, err := call(t, sb, "shell", map[string]any{"action": "close", "session_id": id}); err != nil {
		t.Fatal(err)
	}
	list, err := call(t, sb, "shell", map[string]any{"action": "list"})
	if err != nil || !strings.Contains(list, "没有会话") {
		t.Fatalf("list 应为空: %v %s", err, list)
	}
}

func TestBashCommandsRunsInOrderWithSeparators(t *testing.T) {
	sb := newTestSandbox(t)
	out, err := call(t, sb, "bash", map[string]any{
		"workspace": "w-cmds",
		"commands":  []any{"echo A", "echo B"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"$ echo A", "$ echo B", "退出码 0", "2 条命令"} {
		if !strings.Contains(out, want) {
			t.Fatalf("输出缺少 %q:\n%s", want, out)
		}
	}
	// 顺序与逐条分隔：每条命令的分隔行紧挨着它自己的输出。
	seq := []string{}
	for _, l := range strings.Split(out, "\n") {
		switch l {
		case "$ echo A", "A", "$ echo B", "B":
			seq = append(seq, l)
		}
	}
	if got := strings.Join(seq, "|"); got != "$ echo A|A|$ echo B|B" {
		t.Fatalf("分隔/顺序不对: %s\n%s", got, out)
	}

	// 同一 shell：前面的 cd 对后面的命令生效。
	out, err = call(t, sb, "bash", map[string]any{
		"workspace": "w-cmds",
		"commands":  []string{"mkdir -p sub/dir", "cd sub/dir", "pwd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "sub/dir") {
		t.Fatalf("commands 应在同一个 shell 里顺序执行:\n%s", out)
	}

	// 不隐式 set -e：前一条失败不阻断后一条。
	out, err = call(t, sb, "bash", map[string]any{
		"workspace": "w-cmds", "commands": []any{"false", "echo after-failure"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "after-failure") {
		t.Fatalf("失败的命令不该中断整批:\n%s", out)
	}

	// 分隔行原样显示：命令里的引号/变量/反斜杠不会被 echo 展开。
	out, err = call(t, sb, "bash", map[string]any{
		"workspace": "w-cmds", "commands": []any{`echo "a b" && echo '$HOME' \n`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `$ echo "a b" && echo '$HOME' \n`) {
		t.Fatalf("分隔行应原样显示:\n%s", out)
	}

	// 参数面：一个都没有 / 空数组 / 元素不是字符串 / 空命令。
	if _, err := call(t, sb, "bash", map[string]any{"workspace": "w-cmds"}); err == nil {
		t.Fatal("command 与 commands 都缺应报错")
	}
	if _, err := call(t, sb, "bash", map[string]any{"workspace": "w-cmds", "commands": []any{}}); err == nil {
		t.Fatal("空数组应报错")
	}
	if _, err := call(t, sb, "bash", map[string]any{"workspace": "w-cmds", "commands": []any{"echo A", 7}}); err == nil {
		t.Fatal("非字符串元素应报错")
	}
	if _, err := call(t, sb, "bash", map[string]any{"workspace": "w-cmds", "commands": []any{"echo A", "  "}}); err == nil {
		t.Fatal("空命令应报错")
	}

	// 两者同时给出时以 commands 为准（command 不执行）。
	out, err = call(t, sb, "bash", map[string]any{
		"workspace": "w-cmds", "command": "echo CMD-ONLY", "commands": []any{"echo CMDS-ONLY"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "CMDS-ONLY") || strings.Contains(out, "CMD-ONLY") {
		t.Fatalf("同时给出时应以 commands 为准:\n%s", out)
	}

	// 单条命令仍走原有路径（头行就是命令本身）。
	out, err = call(t, sb, "bash", map[string]any{"workspace": "w-cmds", "command": "echo single-path"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "$ echo single-path\n") {
		t.Fatalf("单条命令的头行应原样展示命令:\n%s", out)
	}
}
