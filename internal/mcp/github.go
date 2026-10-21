package mcp

// GitHub 搜索工具：把「一大堆 GitHub token」变成节点上的一个可轮换的搜索能力。
//
// 为什么放在节点而不是控制端：
//   - 侦察阶段的 GitHub 查询（找公开仓库里的泄露配置、CI 文件、子域线索）本来就该从
//     执行端出口发起，控制端只负责下发意图；
//   - 令牌不经过 MCP 参数（那会被 llm_records / 请求日志留下明文），只从节点本地的
//     600 文件读取，轮换与限流判定都在节点内完成。
//
// 令牌文件：/etc/mcpnode/github_tokens（一行一把；也可用
// MCPNODE_GITHUB_TOKENS_FILE 指到别处）。文件不存在时工具明确报「未配置」，
// 而不是静默返回空结果。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var githubCursor atomic.Uint64

func (s *Sandbox) githubTokensPath() string {
	if p := strings.TrimSpace(os.Getenv("MCPNODE_GITHUB_TOKENS_FILE")); p != "" {
		return p
	}
	return "/etc/mcpnode/github_tokens"
}

// loadGitHubTokens 每次都读文件：轮换令牌不需要重启节点。
func (s *Sandbox) loadGitHubTokens() ([]string, error) {
	raw, err := os.ReadFile(s.githubTokensPath())
	if err != nil {
		return nil, fmt.Errorf("GitHub 令牌文件不可读（%s）：%w；先在该节点写入一行一把的 token", s.githubTokensPath(), err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("GitHub 令牌文件为空：%s", s.githubTokensPath())
	}
	return out, nil
}

type githubSearchResult struct {
	TotalCount int               `json:"total_count"`
	Items      []json.RawMessage `json:"items"`
	Message    string            `json:"message"`
}

func (s *Sandbox) githubTool() *Tool {
	return &Tool{
		Name: "github",
		Description: "GitHub 搜索（节点出口 + 本地令牌池轮换，命中 403/429 自动换 key）：\n" +
			"- action=code：代码搜索，query 支持 GitHub 语法，如 \"example.com password\" 或 org:acme filename:.env\n" +
			"- action=repos：仓库搜索；action=commits：提交搜索；action=issues：issue/PR 搜索\n" +
			"- per_page 默认 10（上限 30）\n" +
			"结果按行给出 html_url + 精简摘要，长文本已截断；需要完整 JSON 用 raw=true。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":   map[string]any{"type": "string", "description": "code | repos | commits | issues"},
				"query":    map[string]any{"type": "string", "description": "GitHub 搜索语法"},
				"per_page": map[string]any{"type": "integer", "description": "条数，默认 10，上限 30"},
				"raw":      map[string]any{"type": "boolean", "description": "返回原始 JSON（默认精简）"},
			},
			"required": []string{"action", "query"},
		},
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			action := strings.ToLower(strings.TrimSpace(argString(args, "action")))
			q := strings.TrimSpace(argString(args, "query"))
			if q == "" {
				return "", fmt.Errorf("query 不能为空")
			}
			perPage := 10
			if v, ok := args["per_page"].(float64); ok && int(v) > 0 {
				perPage = int(v)
			}
			if perPage > 30 {
				perPage = 30
			}
			path := ""
			switch action {
			case "code":
				path = "/search/code"
			case "repos", "repositories":
				path = "/search/repositories"
			case "commits":
				path = "/search/commits"
			case "issues":
				path = "/search/issues"
			default:
				return "", fmt.Errorf("不支持的 action: %q（code | repos | commits | issues）", action)
			}
			tokens, err := s.loadGitHubTokens()
			if err != nil {
				return "", err
			}
			u := "https://api.github.com" + path + "?q=" + url.QueryEscape(q) + fmt.Sprintf("&per_page=%d", perPage)
			if action == "commits" {
				u += "&sort=committer-date&order=desc"
			}
			client := &http.Client{Timeout: 30 * time.Second}
			var body []byte
			var status int
			var lastErr error
			tried := 0
			start := int(githubCursor.Add(1)-1) % len(tokens)
			for i := 0; i < len(tokens) && tried < 6; i++ {
				tok := tokens[(start+i)%len(tokens)]
				tried++
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("Accept", "application/vnd.github+json")
				req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
				req.Header.Set("User-Agent", "mcpnode")
				resp, err := client.Do(req)
				if err != nil {
					lastErr = err
					continue
				}
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
				resp.Body.Close()
				status = resp.StatusCode
				if status == http.StatusOK {
					body = b
					break
				}
				lastErr = fmt.Errorf("HTTP %d: %s", status, snippetBytes(b, 200))
				// 401/403/429 换下一把；422（查询语法错）换也没用，直接返回。
				if status == http.StatusUnprocessableEntity {
					return "", lastErr
				}
			}
			if body == nil {
				if lastErr == nil {
					lastErr = fmt.Errorf("GitHub 搜索失败")
				}
				return "", lastErr
			}
			var parsed githubSearchResult
			if err := json.Unmarshal(body, &parsed); err != nil {
				return snippetBytes(body, 800), nil
			}
			if raw, _ := args["raw"].(bool); raw {
				return snippetBytes(body, 20000), nil
			}
			return formatGitHubHits(action, parsed, perPage), nil
		},
	}
}

// formatGitHubHits 把搜索结果压成「一行一条」的可读文本：模型读得下、也能直接抄链接。
func formatGitHubHits(action string, r githubSearchResult, limit int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "total_count=%d（显示前 %d 条）\n", r.TotalCount, len(r.Items))
	for i, raw := range r.Items {
		if i >= limit {
			break
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		repo := ""
		if rp, ok := m["repository"].(map[string]any); ok {
			repo, _ = rp["full_name"].(string)
		}
		switch action {
		case "code":
			fmt.Fprintf(&b, "- %s:%s | %s\n", repo, str(m["path"]), str(m["html_url"]))
		case "repos":
			fmt.Fprintf(&b, "- %s ★%v | %s | %s\n", str(m["full_name"]), m["stargazers_count"], str(m["html_url"]), truncate(str(m["description"]), 120))
		case "commits":
			msg := ""
			if c, ok := m["commit"].(map[string]any); ok {
				msg = truncate(strings.ReplaceAll(str(c["message"]), "\n", " "), 100)
			}
			fmt.Fprintf(&b, "- %s %s | %s\n", repo, str(m["sha"])[:minInt(12, len(str(m["sha"])))], msg)
		default:
			fmt.Fprintf(&b, "- %s | %s | %s | %s\n", repo, str(m["state"]), truncate(str(m["title"]), 100), str(m["html_url"]))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func snippetBytes(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
