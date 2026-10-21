package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxReadBytes = 512 << 10

func (s *Sandbox) readTool() *Tool {
	return &Tool{
		Name:        "read",
		Description: "读取工作区内文件（默认最多 512KB，可用 offset/limit 分页）。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"workspace": map[string]any{"type": "string"},
				"path":      map[string]any{"type": "string", "description": "工作区内相对路径"},
				"offset":    map[string]any{"type": "number", "description": "起始字节偏移"},
				"limit":     map[string]any{"type": "number", "description": "读取字节数"},
			},
			"required": []string{"workspace", "path"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			path, err := resolveInWorkspace(ws, argString(args, "path"))
			if err != nil {
				return "", err
			}
			f, err := os.Open(path)
			if err != nil {
				return "", fmt.Errorf("打开失败: %w", err)
			}
			defer f.Close()
			offset := int64(clampInt(args, "offset", 0, maxReadBytes))
			limit := int(clampInt(args, "limit", maxReadBytes, maxReadBytes))
			if offset > 0 {
				if _, err := f.Seek(offset, 0); err != nil {
					return "", err
				}
			}
			buf := make([]byte, limit)
			n, err := io.ReadFull(f, buf)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return "", fmt.Errorf("读取失败: %w", err)
			}
			return fmt.Sprintf("%s（%d 字节）:\n%s", argString(args, "path"), n, string(buf[:n])), nil
		},
	}
}

func (s *Sandbox) writeTool() *Tool {
	return &Tool{
		Name:        "write",
		Description: "把内容写入工作区内文件（覆盖），自动创建父目录。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"workspace": map[string]any{"type": "string"},
				"path":      map[string]any{"type": "string"},
				"content":   map[string]any{"type": "string"},
			},
			"required": []string{"workspace", "path", "content"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			path, err := resolveInWorkspace(ws, argString(args, "path"))
			if err != nil {
				return "", err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return "", err
			}
			content := argString(args, "content")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return "", fmt.Errorf("写入失败: %w", err)
			}
			return fmt.Sprintf("已写入 %s（%d 字节）", argString(args, "path"), len(content)), nil
		},
	}
}

func (s *Sandbox) editTool() *Tool {
	return &Tool{
		Name:        "edit",
		Description: "精确替换工作区内文件片段：old 必须唯一命中（除非 replace_all）。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"workspace":   map[string]any{"type": "string"},
				"path":        map[string]any{"type": "string"},
				"old":         map[string]any{"type": "string"},
				"new":         map[string]any{"type": "string"},
				"replace_all": map[string]any{"type": "boolean"},
			},
			"required": []string{"workspace", "path", "old", "new"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			path, err := resolveInWorkspace(ws, argString(args, "path"))
			if err != nil {
				return "", err
			}
			old := argString(args, "old")
			if old == "" {
				return "", fmt.Errorf("old 不能为空")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("读取失败: %w", err)
			}
			text := string(data)
			n := strings.Count(text, old)
			if n == 0 {
				return "", fmt.Errorf("未找到待替换内容")
			}
			all, _ := args["replace_all"].(bool)
			if n > 1 && !all {
				return "", fmt.Errorf("待替换内容出现 %d 次，需要更多上下文或 replace_all=true", n)
			}
			if all {
				text = strings.ReplaceAll(text, old, argString(args, "new"))
			} else {
				text = strings.Replace(text, old, argString(args, "new"), 1)
			}
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				return "", err
			}
			return fmt.Sprintf("已替换 %d 处", n), nil
		},
	}
}

func (s *Sandbox) globTool() *Tool {
	return &Tool{
		Name:        "glob",
		Description: "按 glob 模式列出工作区内文件（如 **/*.txt），按修改时间倒序，最多 500 条。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"workspace": map[string]any{"type": "string"},
				"pattern":   map[string]any{"type": "string"},
			},
			"required": []string{"workspace", "pattern"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			pattern := strings.TrimSpace(argString(args, "pattern"))
			if pattern == "" {
				pattern = "*"
			}
			if filepath.IsAbs(pattern) || strings.Contains(pattern, "..") {
				return "", fmt.Errorf("模式必须是工作区内相对路径（不允许绝对路径或 ..）")
			}
			matches, err := filepath.Glob(filepath.Join(ws, pattern))
			if err != nil {
				return "", fmt.Errorf("glob 失败: %w", err)
			}
			type entry struct {
				path string
				mod  int64
				size int64
			}
			entries := make([]entry, 0, len(matches))
			for _, m := range matches {
				fi, err := os.Stat(m)
				if err != nil {
					continue
				}
				rel, _ := filepath.Rel(ws, m)
				entries = append(entries, entry{path: rel, mod: fi.ModTime().Unix(), size: fi.Size()})
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].mod > entries[j].mod })
			if len(entries) > 500 {
				entries = entries[:500]
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%d 个匹配：\n", len(entries))
			for _, e := range entries {
				fmt.Fprintf(&b, "%s (%d 字节)\n", e.path, e.size)
			}
			return b.String(), nil
		},
	}
}

func (s *Sandbox) grepTool() *Tool {
	return &Tool{
		Name:        "grep",
		Description: "在工作区内按正则搜索文本，返回最多 200 条「文件:行号:内容」。优先用系统 rg，缺失时回落到内置实现。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"workspace":   map[string]any{"type": "string"},
				"pattern":     map[string]any{"type": "string"},
				"path":        map[string]any{"type": "string", "description": "限定子路径，默认整个工作区"},
				"ignore_case": map[string]any{"type": "boolean"},
			},
			"required": []string{"workspace", "pattern"},
		},
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			pattern := strings.TrimSpace(argString(args, "pattern"))
			if pattern == "" {
				return "", fmt.Errorf("pattern 不能为空")
			}
			sub := ws
			if p := strings.TrimSpace(argString(args, "path")); p != "" {
				sub, err = resolveInWorkspace(ws, p)
				if err != nil {
					return "", err
				}
			}
			ignoreCase, _ := args["ignore_case"].(bool)
			flags := "-n --max-count 200"
			if ignoreCase {
				flags += " -i"
			}
			cmdline := fmt.Sprintf("rg %s -e %s . || true", flags, shellQuote(pattern))
			out, err := s.runSync(ctx, ws, "cd "+shellQuote(sub)+" && "+cmdline, 60*time.Second)
			if err != nil {
				return "", err
			}
			if strings.Contains(out, "command not found") || strings.Contains(out, "rg: not found") {
				return s.grepFallback(sub, pattern, ignoreCase)
			}
			return out, nil
		},
	}
}

// grepFallback 在 rg 缺失时用 Go 实现顶一下：目录遍历 + 正则匹配，跳过二进制与大文件。
func (s *Sandbox) grepFallback(root, pattern string, ignoreCase bool) (string, error) {
	expr := pattern
	if ignoreCase {
		expr = "(?i)" + pattern
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return "", fmt.Errorf("正则无效: %w", err)
	}
	var b strings.Builder
	hits := 0
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || hits >= 200 {
			return nil
		}
		if info.IsDir() || info.Size() > 2<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes0(data) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				fmt.Fprintf(&b, "%s:%d:%s\n", rel, i+1, line)
				hits++
				if hits >= 200 {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if hits == 0 {
		return "（无匹配；rg 未安装，使用内置回退实现）", nil
	}
	return "（rg 未安装，使用内置回退实现）\n" + b.String(), nil
}

func bytes0(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

func (s *Sandbox) lsTool() *Tool {
	return &Tool{
		Name:        "ls",
		Description: "列出工作区内目录内容（含大小与类型）。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"workspace": map[string]any{"type": "string"}, "path": map[string]any{"type": "string"}},
			"required":   []string{"workspace"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			dir, err := resolveInWorkspace(ws, argString(args, "path"))
			if err != nil {
				return "", err
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return "", fmt.Errorf("读取目录失败: %w", err)
			}
			var b strings.Builder
			for _, e := range entries {
				info, _ := e.Info()
				kind := "文件"
				size := int64(0)
				if e.IsDir() {
					kind = "目录"
				} else if info != nil {
					size = info.Size()
				}
				fmt.Fprintf(&b, "%-4s %10d  %s\n", kind, size, e.Name())
			}
			fmt.Fprintf(&b, "共 %d 项（%s）", len(entries), dir)
			return b.String(), nil
		},
	}
}

func clampInt(args map[string]any, key string, def, max int) int {
	v, ok := numericArg(args[key])
	if !ok || v < 0 {
		v = def
	}
	if max > 0 && v > max {
		v = max
	}
	return v
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
