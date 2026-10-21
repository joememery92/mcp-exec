package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// 产物清单与分块读取（执行端分离 P4）：控制端回传校验的执行端一半。
//
// 执行端负责跑工具、把产物留在工作区；权威副本在控制端。回传时要能回答两个问题：
// ① 工作区里到底有哪些文件、大小与整文件 sha256 是什么（manifest）；
// ② 不装 rsync、或文件太大时怎么按需取回（read 分块，块拼回来的哈希必须等于清单里的值）。
// 因此这里只读工作区、不写任何文件，也不保存状态。
const (
	artifactDefaultReadBytes  = 1 << 20 // 分块读默认 1MiB
	artifactMaxReadBytes      = 4 << 20 // 单次分块上限 4MiB
	artifactHashLimitDefault  = 256 << 20
	artifactMaxEntriesDefault = 20000
)

// artifactFile 是清单里的一条。sha256 为整文件哈希；超过上限时给 "skipped:too-large"。
type artifactFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type artifactManifest struct {
	Workspace  string         `json:"workspace"`
	Files      []artifactFile `json:"files"`
	TotalBytes int64          `json:"total_bytes"`
	FilesCount int            `json:"files_count"`
	Warnings   []string       `json:"warnings,omitempty"`
}

type artifactChunk struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"` // 整文件哈希，不是本块的
	EOF    bool   `json:"eof"`
	Base64 string `json:"base64"`
}

func (s *Sandbox) artifactsTool() *Tool {
	return &Tool{
		Name: "artifacts",
		Description: "产物清单与分块读取（控制端回传校验用）：\n" +
			"- action=manifest：返回工作区内所有普通文件的 JSON 清单（path/size/sha256、total_bytes、files_count）；" +
			"跳过 .jobs/ 与 .tmp/，路径为工作区内相对路径（/ 分隔）；单文件超过 256MiB 只记大小、sha256 给 skipped:too-large；" +
			"条目上限 20000，超出按路径排序截断并写进 warnings。\n" +
			"- action=read：分块读取一个文件，参数 path 与可选 offset/length（默认 0/1MiB，上限 4MiB），" +
			"返回 base64 内容、整文件 sha256 与 eof；用于大文件或没有 rsync 时兜底拉取。" +
			"大文件按块拉取时传 skip_hash=true 可跳过每块重算整文件哈希（sha256 返回空串，整文件校验以 manifest 为准）。\n" +
			"两个 action 都只接受工作区内相对路径。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":    map[string]any{"type": "string", "description": "manifest | read"},
				"workspace": map[string]any{"type": "string", "description": "工作区名"},
				"path":      map[string]any{"type": "string", "description": "action=read 时的工作区内相对路径"},
				"offset":    map[string]any{"type": "number", "description": "action=read 的起始字节偏移，默认 0"},
				"length":    map[string]any{"type": "number", "description": "action=read 的读取字节数，默认 1MiB，上限 4MiB"},
				"skip_hash": map[string]any{"type": "boolean", "description": "action=read 时跳过整文件 sha256（大文件分块拉取用；此时 sha256 为空，改用 manifest 校验整文件）"},
			},
			"required": []string{"workspace"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			switch action := strings.ToLower(strings.TrimSpace(argString(args, "action"))); action {
			case "", "manifest":
				return s.artifactManifest(ws)
			case "read":
				return s.artifactRead(ws, args)
			default:
				return "", fmt.Errorf("未知 action %q（只支持 manifest | read）", action)
			}
		},
	}
}

// artifactSkipDir 报告该目录名是否是执行端的内部目录：.jobs 是后台任务日志，
// .tmp 是工具落地的中间文件，两者都不属于要回传的产物。
func artifactSkipDir(name string) bool {
	return name == ".jobs" || name == ".tmp"
}

func (s *Sandbox) artifactManifest(ws string) (string, error) {
	type entry struct {
		path string
		size int64
	}
	entries := []entry{}
	warnings := []string{}

	walkErr := filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == ws {
				return err
			}
			// 单个条目在遍历时消失或不可读（扫描类任务同时在写工作区）不该让整份清单失败。
			return nil
		}
		if d.IsDir() {
			if p != ws && artifactSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // 符号链接、设备、套接字不是产物
		}
		rel, relErr := filepath.Rel(ws, p)
		if relErr != nil {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		entries = append(entries, entry{path: filepath.ToSlash(rel), size: info.Size()})
		return nil
	})
	if walkErr != nil {
		return "", fmt.Errorf("遍历工作区失败: %w", walkErr)
	}

	// 清单顺序必须与节点无关：按路径排序后再截断，控制端才能稳定比对。
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	if max := s.artifactMaxEntries; max > 0 && len(entries) > max {
		warnings = append(warnings, fmt.Sprintf("文件总数 %d 超过上限 %d，清单已按路径排序截断", len(entries), max))
		entries = entries[:max]
	}

	files := make([]artifactFile, 0, len(entries))
	var total int64
	for _, e := range entries {
		if s.artifactHashLimit > 0 && e.size > s.artifactHashLimit {
			files = append(files, artifactFile{Path: e.path, Size: e.size, SHA256: "skipped:too-large"})
			warnings = append(warnings, fmt.Sprintf("%s: %d 字节超过 %d 字节哈希上限，未计算 sha256（可用 action=read 分块取回）",
				e.path, e.size, s.artifactHashLimit))
			total += e.size
			continue
		}
		sum, err := fileSHA256(filepath.Join(ws, filepath.FromSlash(e.path)))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: 读取失败，已从清单剔除（%v）", e.path, err))
			continue
		}
		files = append(files, artifactFile{Path: e.path, Size: e.size, SHA256: sum})
		total += e.size
	}

	out, err := json.Marshal(artifactManifest{
		Workspace:  filepath.Base(ws),
		Files:      files,
		TotalBytes: total,
		FilesCount: len(files),
		Warnings:   warnings,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (s *Sandbox) artifactRead(ws string, args map[string]any) (string, error) {
	rel := strings.TrimSpace(argString(args, "path"))
	if rel == "" {
		return "", fmt.Errorf("action=read 需要 path")
	}
	path, err := resolveInWorkspace(ws, rel)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("打开失败: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.IsDir() || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("只支持工作区内的普通文件: %q", rel)
	}
	size := fi.Size()

	offset := int64(0)
	if v, ok := numericArg(args["offset"]); ok && v > 0 {
		offset = int64(v)
	}
	if offset > size {
		offset = size
	}
	length := artifactDefaultReadBytes
	if v, ok := numericArg(args["length"]); ok && v > 0 {
		length = v
	}
	if length > artifactMaxReadBytes {
		length = artifactMaxReadBytes
	}

	// 整文件哈希：分块拉回后由控制端拼接，通常要能和清单里的同一字段对上。
	// 但每个块都重算整个文件是 O(n²) 读盘——大文件按块拉取时调用方应传 skip_hash=true，
	// 改为用 manifest 里的 sha256 校验拼接结果；默认行为保持不变。
	sum := ""
	if skipHash, _ := args["skip_hash"].(bool); !skipHash {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", fmt.Errorf("计算哈希失败: %w", err)
		}
		sum = hex.EncodeToString(h.Sum(nil))
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", fmt.Errorf("定位失败: %w", err)
	}
	buf := make([]byte, length)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", fmt.Errorf("读取失败: %w", err)
	}

	out, err := json.Marshal(artifactChunk{
		Path:   filepath.ToSlash(filepath.Clean(rel)),
		Size:   size,
		Offset: offset,
		Length: n,
		SHA256: sum,
		EOF:    offset+int64(n) >= size,
		Base64: base64.StdEncoding.EncodeToString(buf[:n]),
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
