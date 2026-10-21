package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestSandbox(t *testing.T) *Sandbox {
	t.Helper()
	sb := New(t.TempDir())
	sb.Home = t.TempDir() // 与生产一致：HOME 是节点上的真实目录，绝不是工作区
	sb.MaxSync = 10 * time.Second
	sb.MaxAsync = 30 * time.Second
	return sb
}

func call(t *testing.T, sb *Sandbox, tool string, args map[string]any) (string, error) {
	t.Helper()
	impl, ok := sb.byName[tool]
	if !ok {
		t.Fatalf("工具不存在: %s", tool)
	}
	return impl.Call(context.Background(), args)
}

// 工作区名与相对路径都不能跑出工作区——执行面读不到宿主机的其它文件。
func TestWorkspaceConfinement(t *testing.T) {
	sb := newTestSandbox(t)
	for _, bad := range []string{"../escape", "a/b", "/etc", "..", "", "a b"} {
		if _, err := sb.workspace(bad); err == nil {
			t.Fatalf("工作区名 %q 应被拒绝", bad)
		}
	}
	ws, err := sb.workspace("task-1")
	if err != nil {
		t.Fatalf("合法工作区被拒: %v", err)
	}
	for _, bad := range []string{"../x", "/etc/passwd", "a/../../b", "~/x"} {
		if _, err := resolveInWorkspace(ws, bad); err == nil {
			t.Fatalf("路径 %q 应被拒绝", bad)
		}
	}
	if got, err := resolveInWorkspace(ws, "sub/dir/f.txt"); err != nil || !strings.HasPrefix(got, ws) {
		t.Fatalf("合法相对路径被拒: %s %v", got, err)
	}
}

func TestBashSyncRunsAndTimesOut(t *testing.T) {
	sb := newTestSandbox(t)
	out, err := call(t, sb, "bash", map[string]any{
		"workspace": "w1", "command": "echo hello-from-sandbox && pwd",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "hello-from-sandbox") || !strings.Contains(out, "退出码 0") {
		t.Fatalf("输出异常: %s", out)
	}
	if !strings.Contains(out, "w1") {
		t.Fatalf("命令应工作在执行面的工作区里: %s", out)
	}
	// 超时：命令自己睡 5 秒，上限 1 秒
	start := time.Now()
	out, err = call(t, sb, "bash", map[string]any{
		"workspace": "w1", "command": "sleep 5", "timeout_sec": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "超时被杀") {
		t.Fatalf("应报超时: %s", out)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("超时未生效，实际耗时 %s", elapsed)
	}
}

func TestAsyncJobLifecycle(t *testing.T) {
	sb := newTestSandbox(t)
	out, err := call(t, sb, "bash_async", map[string]any{
		"workspace": "w2", "command": "echo started; sleep 30; echo never",
	})
	if err != nil {
		t.Fatal(err)
	}
	jobID := ""
	for _, f := range strings.Fields(out) {
		if len(f) == 16 {
			jobID = f
			break
		}
	}
	if jobID == "" {
		t.Fatalf("未取到 job id: %s", out)
	}

	time.Sleep(300 * time.Millisecond)
	status, err := call(t, sb, "job_status", map[string]any{"job_id": jobID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "running") {
		t.Fatalf("应处于 running: %s", status)
	}
	read, err := call(t, sb, "job_read", map[string]any{"job_id": jobID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read, "started") {
		t.Fatalf("日志应含 started: %s", read)
	}
	if _, err := call(t, sb, "job_kill", map[string]any{"job_id": jobID}); err != nil {
		t.Fatal(err)
	}
	status, err = call(t, sb, "job_status", map[string]any{"job_id": jobID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "killed") && !strings.Contains(status, "failed") {
		t.Fatalf("终止后状态应为 killed/failed: %s", status)
	}
	if _, err := call(t, sb, "job_status", map[string]any{"job_id": "ffffffffffffffff"}); err == nil {
		t.Fatal("未知 job 应报错")
	}
}

func TestFilesystemTools(t *testing.T) {
	sb := newTestSandbox(t)
	if _, err := call(t, sb, "write", map[string]any{
		"workspace": "fs", "path": "notes/a.txt", "content": "alpha\nbeta\n",
	}); err != nil {
		t.Fatal(err)
	}
	read, err := call(t, sb, "read", map[string]any{"workspace": "fs", "path": "notes/a.txt"})
	if err != nil || !strings.Contains(read, "beta") {
		t.Fatalf("read 失败: %v %s", err, read)
	}
	if _, err := call(t, sb, "edit", map[string]any{
		"workspace": "fs", "path": "notes/a.txt", "old": "beta", "new": "gamma",
	}); err != nil {
		t.Fatal(err)
	}
	read, _ = call(t, sb, "read", map[string]any{"workspace": "fs", "path": "notes/a.txt"})
	if !strings.Contains(read, "gamma") || strings.Contains(read, "beta") {
		t.Fatalf("edit 未生效: %s", read)
	}
	if _, err := call(t, sb, "edit", map[string]any{
		"workspace": "fs", "path": "notes/a.txt", "old": "不存在的内容", "new": "x",
	}); err == nil {
		t.Fatal("未命中时应报错")
	}
	ls, err := call(t, sb, "ls", map[string]any{"workspace": "fs", "path": "notes"})
	if err != nil || !strings.Contains(ls, "a.txt") {
		t.Fatalf("ls 失败: %v %s", err, ls)
	}
	gl, err := call(t, sb, "glob", map[string]any{"workspace": "fs", "pattern": "notes/*.txt"})
	if err != nil || !strings.Contains(gl, "a.txt") {
		t.Fatalf("glob 失败: %v %s", err, gl)
	}
	gr, err := call(t, sb, "grep", map[string]any{"workspace": "fs", "pattern": "gam"})
	if err != nil || !strings.Contains(gr, "a.txt") {
		t.Fatalf("grep 失败: %v %s", err, gr)
	}
	// 越界读必须失败
	if _, err := call(t, sb, "read", map[string]any{"workspace": "fs", "path": "../../etc/passwd"}); err == nil {
		t.Fatal("越界路径应被拒绝")
	}
}

func TestReconRequiresScripts(t *testing.T) {
	sb := newTestSandbox(t)
	// 测试环境没有侦察脚本：把脚本目录指到空目录，断言错误是"脚本缺失"，
	// 而不是崩溃、静默成功、或者真去扫 example.com。
	t.Setenv("MCPNODE_RECON_SCRIPTS", t.TempDir())
	_, err := call(t, sb, "recon", map[string]any{"action": "subfind", "target": "example.com", "workspace": "r1"})
	if err == nil || !strings.Contains(err.Error(), "脚本缺失") {
		t.Fatalf("应报脚本缺失，实际: %v", err)
	}
	if _, err := call(t, sb, "recon", map[string]any{"action": "nope", "target": "x", "workspace": "r1"}); err == nil {
		t.Fatal("未知 action 应报错")
	}
}

// MCP 协议面：initialize 发会话、tools/list 有工具、tools/call 返回 content，
// 以及令牌校验——没有令牌的调用一律 401。
func TestMCPProtocolAndAuth(t *testing.T) {
	sb := newTestSandbox(t)
	sb.Token = "s3cret"
	srv := httptest.NewServer(sb.Handler())
	defer srv.Close()

	post := func(body string, auth string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		return resp, out
	}

	resp, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，得到 %d", resp.StatusCode)
	}

	resp, body := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, "s3cret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize 失败: %d", resp.StatusCode)
	}
	if resp.Header.Get("Mcp-Session-Id") == "" {
		t.Fatal("initialize 应返回 Mcp-Session-Id")
	}
	result, _ := body["result"].(map[string]any)
	if result["protocolVersion"] != protocolVersion {
		t.Fatalf("协议版本不符: %v", result["protocolVersion"])
	}

	_, body = post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "s3cret")
	tools, _ := body["result"].(map[string]any)["tools"].([]any)
	if len(tools) < 10 {
		t.Fatalf("工具太少: %d", len(tools))
	}
	names := map[string]bool{}
	for _, raw := range tools {
		names[raw.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"bash", "bash_async", "job_status", "read", "write", "recon", "env_card"} {
		if !names[want] {
			t.Fatalf("缺少工具 %s（现有 %v）", want, names)
		}
	}

	_, body = post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bash","arguments":{"workspace":"mcp","command":"echo via-mcp"}}}`, "s3cret")
	content, _ := body["result"].(map[string]any)["content"].([]any)
	if len(content) == 0 || !strings.Contains(content[0].(map[string]any)["text"].(string), "via-mcp") {
		t.Fatalf("tools/call 输出异常: %v", body)
	}

	// 未知工具不是协议错误，而是 isError=true 的结果
	_, body = post(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}`, "s3cret")
	if errFlag, _ := body["result"].(map[string]any)["isError"].(bool); !errFlag {
		t.Fatalf("未知工具应返回 isError: %v", body)
	}

	// 通知不回包（202）
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp",
		bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)))
	req.Header.Set("Authorization", "Bearer s3cret")
	nresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer nresp.Body.Close()
	if nresp.StatusCode != http.StatusAccepted {
		t.Fatalf("通知应 202，得到 %d", nresp.StatusCode)
	}
}

func TestCommandEnvKeepsHomeAndStripsInjection(t *testing.T) {
	sb := newTestSandbox(t)
	ws, err := sb.workspace("env")
	if err != nil {
		t.Fatal(err)
	}
	has := func(prefix string) bool {
		for _, kv := range sb.commandEnv(ws) {
			if strings.HasPrefix(kv, prefix) {
				return true
			}
		}
		return false
	}
	// HOME 必须被显式设成节点上的真实 HOME（而不是工作区、也不是空值）：
	// nuclei 靠它找 /root/nuclei-templates；空值会让 PD 工具把缓存建到工作区。
	if !has("HOME="+sb.Home) || sb.Home == "" {
		t.Fatalf("commandEnv 应注入非空 HOME，实际 %q", sb.Home)
	}
	if has("HOME=" + ws) {
		t.Fatal("HOME 不应指向工作区")
	}
	for _, banned := range []string{"ENV=", "BASH_ENV=", "PROMPT_COMMAND="} {
		if has(banned) {
			t.Fatalf("%s 必须被剥离（能在每个新 shell 里注入执行）", banned)
		}
	}
	if !has("MCPNODE_WORKSPACE=" + ws) {
		t.Fatal("应注入 MCPNODE_WORKSPACE")
	}
}

func TestExtractVersionSkipsCommandHeader(t *testing.T) {
	out := "$ '/opt/mcpnode/data/tools/subfinder' -version 2>&1 | head -4 || true\n(退出码 0, 耗时 0.1s)\n_banner_\n[INF] current version v2.17.0\n"
	if got := extractVersion(out); got != "v2.17.0" {
		t.Fatalf("版本解析错误: %q", got)
	}
	if got := extractVersion("$ cmd\n(退出码 1, 耗时 0.0s)\nboom\n"); got != "已安装（版本未知）" {
		t.Fatalf("无版本号时应回落: %q", got)
	}
}

func TestNumericArgAcceptsJSONAndGoInts(t *testing.T) {
	// JSON 解出来是 float64，Go 调用方常传 int：两者都必须生效，
	// 否则会出现"参数写了没生效，只有线上（HTTP）正常"的假象。
	for _, v := range []any{float64(5), 5, int64(5), "5"} {
		if got, ok := numericArg(v); !ok || got != 5 {
			t.Fatalf("numericArg(%T) = %d,%v", v, got, ok)
		}
	}
	if _, ok := numericArg("abc"); ok {
		t.Fatal("非数字不应解析成功")
	}
}

func TestEnvCardMentionsProxyAndWorkspace(t *testing.T) {
	sb := newTestSandbox(t)
	sb.Proxy = "http://127.0.0.1:18788"
	sb.EgressIP = "203.0.113.9"
	out, err := call(t, sb, "env_card", map[string]any{"workspace": "ec"})
	if err != nil {
		t.Fatal(err)
	}
	// 代理地址的主机部分不下发给调用方（部分部署形态下它就是控制端地址），
	// 只保留协议与端口；出口 IP、工作区根、长任务提示仍然要能看到。
	for _, want := range []string{"http://<录制端>:18788", "203.0.113.9", sb.Root, "bash_async"} {
		if !strings.Contains(out, want) {
			t.Fatalf("环境卡缺少 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "127.0.0.1:18788") {
		t.Fatalf("环境卡泄露了代理主机:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(sb.Root, "ec")); err != nil {
		t.Fatalf("工作区未创建: %v", err)
	}
}
