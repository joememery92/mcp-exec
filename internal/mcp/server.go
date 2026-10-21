// Package mcp 实现 远程执行端 MCP 服务：一个只跑工具调用的 MCP server。
//
// 定位：控制端（本机）持有一切真相——事实图、证据、流量、报告；执行端（节点）
// 只负责"跑命令、读写工作区、回传产物"。因此这里刻意不保存任何权威状态：
// 唯一驻留的是 job 句柄与工作区文件，两者都有 TTL，节点随时可以整机丢弃。
//
// 传输按 MCP "Streamable HTTP" 实现（JSON-RPC over POST），与 mcphttp 客户端一致，
// 因此任何 MCP 客户端都能直接把它当工具源使用。
package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/joememery92/mcp-exec/internal/recording"
)

const protocolVersion = "2025-06-18"

// Tool 是一个可被调用的工具实现。Result 的文本会作为 MCP content 返回。
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
	Call        func(ctx context.Context, args map[string]any) (string, error)
}

// Sandbox 是执行端的全部状态：工作区根目录、出口代理、工具表。
type Sandbox struct {
	Root     string        // 工作区根目录（如 /var/lib/mcpnode/ws）
	Home     string        // 命令的 HOME：nuclei/httpx 等按它找模板与配置，绝不能指向工作区
	Proxy    string        // 录制代理（HTTP(S)_PROXY），HTTP 流量因此回到本机流量库
	CACert   string        // 录制代理 CA（SSL_CERT_FILE）
	EgressIP string        // 对外 IP（env_card 用；不主动探测外部服务）
	MaxSync  time.Duration // 同步工具上限
	MaxAsync time.Duration // 后台任务上限
	Token    string        // 调用令牌；空 = 不校验（仅开发用）

	// Traffic 是节点自带的本地录制器（启动时 -record 才有）。工具层只做"把某个
	// 时间窗导出成 ImportArchive 能读的目录"，录制本身由 traffic 包负责。
	Traffic *recording.Traffic

	// artifacts 工具的边界：单文件超过 artifactHashLimit 时只记大小不哈希，
	// 清单条目超过 artifactMaxEntries 时按路径排序截断。测试会改小它们。
	artifactHashLimit  int64
	artifactMaxEntries int

	tools  []*Tool
	byName map[string]*Tool

	jobs   *jobManager
	shells *shellManager

	mu       sync.Mutex
	sessions map[string]time.Time
}

// New 组装沙箱：注册全部工具。
func New(root string) *Sandbox {
	s := &Sandbox{
		Root:     root,
		MaxSync:  300 * time.Second,
		MaxAsync: 30 * time.Minute,
		jobs:     newJobManager(),
		shells:   newShellManager(),
		sessions: map[string]time.Time{},

		artifactHashLimit:  artifactHashLimitDefault,
		artifactMaxEntries: artifactMaxEntriesDefault,
	}
	s.tools = []*Tool{
		s.bashTool(),
		s.bashAsyncTool(),
		s.jobStatusTool(),
		s.jobReadTool(),
		s.jobKillTool(),
		s.shellTool(),
		s.readTool(),
		s.writeTool(),
		s.editTool(),
		s.globTool(),
		s.grepTool(),
		s.lsTool(),
		s.reconTool(),
		s.githubTool(),
		s.envCardTool(),
		s.artifactsTool(),
		s.workspacesTool(),
		s.trafficExportTool(),
	}
	s.byName = make(map[string]*Tool, len(s.tools))
	for _, t := range s.tools {
		s.byName[t.Name] = t
	}
	return s
}

// handler 返回挂载好的 HTTP handler：POST /mcp 是 MCP 端点，GET /healthz 供电厂与
// doctor 探活，其余一律 404。
func (s *Sandbox) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handleMCP)
	mux.HandleFunc("/healthz", s.handleHealth)
	return mux
}

func (s *Sandbox) handleHealth(w http.ResponseWriter, _ *http.Request) {
	jobs := s.jobs.count()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "service": "mcpnode", "workspaces": s.Root,
		"running_jobs": jobs, "shell_sessions": s.shells.count(), "tools": len(s.tools),
	})
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (s *Sandbox) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Streamable HTTP 的 DELETE 用于结束会话；其余方法不支持。
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	var req rpcRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "解析请求失败: " + err.Error()}})
		return
	}

	// 通知（无 id）不回包，按规范返回 202。
	if len(req.ID) == 0 || string(req.ID) == "null" {
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		session := randomID()
		s.mu.Lock()
		s.sessions[session] = time.Now()
		s.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", session)
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "mcpnode", "version": Version},
		}})
	case "ping":
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
	case "tools/list":
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": s.toolListings()}})
	case "tools/call":
		s.handleToolCall(r.Context(), w, req)
	default:
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32601, Message: "不支持的方法: " + req.Method}})
	}
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func (s *Sandbox) handleToolCall(ctx context.Context, w http.ResponseWriter, req rpcRequest) {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32602, Message: "参数解析失败: " + err.Error()}})
		return
	}
	tool, ok := s.byName[p.Name]
	if !ok {
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: toolError("未知工具: " + p.Name)})
		return
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}
	started := time.Now()
	out, err := tool.Call(ctx, p.Arguments)
	elapsed := time.Since(started)
	if err != nil {
		log.Printf("[mcpnode] %s 失败(%.1fs): %v", p.Name, elapsed.Seconds(), err)
		writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: toolError(err.Error())})
		return
	}
	log.Printf("[mcpnode] %s 完成(%.1fs, %d 字节)", p.Name, elapsed.Seconds(), len(out))
	writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": out}},
		"isError": false,
	}})
}

func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}

type toolListing struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func (s *Sandbox) toolListings() []toolListing {
	out := make([]toolListing, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, toolListing{Name: t.Name, Description: t.Description, InputSchema: t.Schema})
	}
	return out
}

func (s *Sandbox) authorized(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Sandbox) String() string {
	return fmt.Sprintf("mcpnode root=%s tools=%d", s.Root, len(s.tools))
}
