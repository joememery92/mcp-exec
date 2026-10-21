package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func artifactManifestOf(t *testing.T, sb *Sandbox, workspace string) artifactManifest {
	t.Helper()
	out, err := call(t, sb, "artifacts", map[string]any{"action": "manifest", "workspace": workspace})
	if err != nil {
		t.Fatalf("manifest 失败: %v", err)
	}
	var m artifactManifest
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("manifest 不是合法 JSON: %v\n%s", err, out)
	}
	return m
}

func artifactReadOf(t *testing.T, sb *Sandbox, args map[string]any) artifactChunk {
	t.Helper()
	out, err := call(t, sb, "artifacts", args)
	if err != nil {
		t.Fatalf("read 失败: %v", err)
	}
	var c artifactChunk
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("read 不是合法 JSON: %v\n%s", err, out)
	}
	return c
}

func shaOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// 清单只覆盖要回传的产物：.jobs（后台任务日志）与 .tmp（中间文件）必须被跳过，
// 路径是工作区内相对路径且用 / 分隔。
func TestArtifactsManifestSkipsInternalDirs(t *testing.T) {
	sb := newTestSandbox(t)
	ws, err := sb.workspace("t1i2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, sb, "write", map[string]any{
		"workspace": "t1i2", "path": "recon/a.txt", "content": "alpha\n",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "top.json"), []byte(`{"k":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".jobs/0123456789abcdef.log", ".tmp/partial.part", "nested/.tmp/junk"} {
		full := filepath.Join(ws, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("internal"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := artifactManifestOf(t, sb, "t1i2")
	if m.Workspace != "t1i2" {
		t.Fatalf("workspace 字段错误: %q", m.Workspace)
	}
	got := map[string]artifactFile{}
	for _, f := range m.Files {
		got[f.Path] = f
	}
	if len(got) != 2 {
		t.Fatalf("应只列出 2 个产物，实际 %d: %+v", len(got), m.Files)
	}
	for _, want := range []string{"recon/a.txt", "top.json"} {
		f, ok := got[want]
		if !ok {
			t.Fatalf("清单缺少 %s: %+v", want, m.Files)
		}
		if f.Size <= 0 || f.SHA256 == "" {
			t.Fatalf("%s 条目字段不全: %+v", want, f)
		}
	}
	for _, banned := range []string{".jobs/0123456789abcdef.log", ".tmp/partial.part", "nested/.tmp/junk"} {
		if _, ok := got[banned]; ok {
			t.Fatalf("内部目录 %s 不应出现在清单里: %+v", banned, m.Files)
		}
	}
	// 路径必须与节点无关：/ 分隔、相对工作区。
	for p := range got {
		if strings.Contains(p, `\`) || strings.HasPrefix(p, "/") {
			t.Fatalf("清单路径格式错误: %q", p)
		}
	}
	if data, err := os.ReadFile(filepath.Join(ws, "recon", "a.txt")); err != nil || got["recon/a.txt"].SHA256 != shaOf(data) {
		t.Fatalf("sha256 与文件内容不符: %v %+v", err, got["recon/a.txt"])
	}
	if m.FilesCount != len(m.Files) || m.TotalBytes != got["recon/a.txt"].Size+got["top.json"].Size {
		t.Fatalf("统计字段不一致: count=%d total=%d files=%+v", m.FilesCount, m.TotalBytes, m.Files)
	}
	// 空工作区必须给 []，不是 null——控制面会直接遍历这个数组。
	empty := artifactManifestOf(t, sb, "empty-ws")
	if empty.FilesCount != 0 || empty.Files == nil || empty.TotalBytes != 0 {
		t.Fatalf("空工作区清单应为空数组: %+v", empty)
	}
}

// 分块读取的核心约束：每块返回的 sha256 都是整文件哈希（不是本块），
// 因此块拼回来必须既能对上清单哈希，也能还原原文件。
func TestArtifactsReadMatchesManifestHashAndChunks(t *testing.T) {
	sb := newTestSandbox(t)
	ws, err := sb.workspace("chunks")
	if err != nil {
		t.Fatal(err)
	}
	content := make([]byte, 300_000)
	for i := range content {
		content[i] = byte((i*37 + 11) % 251)
	}
	if err := os.WriteFile(filepath.Join(ws, "big.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	want := shaOf(content)

	m := artifactManifestOf(t, sb, "chunks")
	if len(m.Files) != 1 || m.Files[0].Path != "big.bin" || m.Files[0].SHA256 != want {
		t.Fatalf("清单哈希错误: %+v (want %s)", m.Files, want)
	}

	// 默认读：整文件小于 1MiB 时应一次读完并 eof=true。
	whole := artifactReadOf(t, sb, map[string]any{
		"action": "read", "workspace": "chunks", "path": "big.bin",
	})
	if whole.SHA256 != want || whole.Size != int64(len(content)) || !whole.EOF || whole.Length != len(content) {
		t.Fatalf("整文件读取字段错误: size=%d len=%d eof=%v sha=%s", whole.Size, whole.Length, whole.EOF, whole.SHA256)
	}
	if data, err := base64.StdEncoding.DecodeString(whole.Base64); err != nil || !bytes.Equal(data, content) {
		t.Fatalf("整文件 base64 解码不一致: %v", err)
	}

	// 分块读：每块都带整文件哈希，拼接后等于原文件。
	const chunkSize = 40_000
	var joined []byte
	offset := 0
	for i := 0; ; i++ {
		c := artifactReadOf(t, sb, map[string]any{
			"action": "read", "workspace": "chunks", "path": "big.bin",
			"offset": offset, "length": chunkSize,
		})
		if i > 20 {
			t.Fatal("分块读取未在预期次数内结束")
		}
		if c.SHA256 != want {
			t.Fatalf("第 %d 块的 sha256 应是整文件哈希，得到 %s", i, c.SHA256)
		}
		if c.Offset != int64(offset) {
			t.Fatalf("第 %d 块 offset 回显错误: %d", i, c.Offset)
		}
		part, err := base64.StdEncoding.DecodeString(c.Base64)
		if err != nil {
			t.Fatalf("第 %d 块 base64 解码失败: %v", i, err)
		}
		if c.Length != len(part) {
			t.Fatalf("第 %d 块 length 与实际内容不符: %d/%d", i, c.Length, len(part))
		}
		if end := offset + len(part); end > len(content) || !bytes.Equal(part, content[offset:end]) {
			t.Fatalf("第 %d 块内容与原文不符 (offset=%d len=%d)", i, offset, len(part))
		}
		joined = append(joined, part...)
		if c.EOF {
			break
		}
		if len(part) == 0 {
			t.Fatal("既未 eof 又读到 0 字节，会死循环")
		}
		offset += len(part)
	}
	if !bytes.Equal(joined, content) {
		t.Fatalf("分块拼接后与原文件不一致: %d/%d 字节", len(joined), len(content))
	}

	// offset 超过文件末尾：给空内容 + eof，而不是报错或回绕。
	tail := artifactReadOf(t, sb, map[string]any{
		"action": "read", "workspace": "chunks", "path": "big.bin", "offset": 10_000_000, "length": 1024,
	})
	if !tail.EOF || tail.Length != 0 || tail.Base64 != "" || tail.Offset != int64(len(content)) {
		t.Fatalf("越界 offset 应回落为空内容 + eof: %+v", tail)
	}
}

// skip_hash 只关掉"每块重算整文件哈希"这一步（大文件分块拉取否则是 O(n²) 读盘），
// 内容与 eof 语义不变；默认仍返回真实哈希。
func TestArtifactsReadSkipHash(t *testing.T) {
	sb := newTestSandbox(t)
	ws, err := sb.workspace("skiphash")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	if err := os.WriteFile(filepath.Join(ws, "c.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}

	// 默认（skip_hash 缺省/false）：整文件哈希必须存在。
	def := artifactReadOf(t, sb, map[string]any{
		"action": "read", "workspace": "skiphash", "path": "c.txt", "offset": 0, "length": 8,
	})
	if def.SHA256 != shaOf(content) {
		t.Fatalf("默认应返回整文件哈希: %q (want %s)", def.SHA256, shaOf(content))
	}

	// skip_hash=true：sha256 为空串，内容/offset/eof 语义不变。
	sk := artifactReadOf(t, sb, map[string]any{
		"action": "read", "workspace": "skiphash", "path": "c.txt",
		"offset": 10, "length": 5, "skip_hash": true,
	})
	if sk.SHA256 != "" {
		t.Fatalf("skip_hash=true 时 sha256 应为空: %q", sk.SHA256)
	}
	if sk.Offset != 10 || sk.Length != 5 || sk.Size != int64(len(content)) || sk.EOF {
		t.Fatalf("skip_hash=true 不应改变其它字段: %+v", sk)
	}
	if part, err := base64.StdEncoding.DecodeString(sk.Base64); err != nil || !bytes.Equal(part, content[10:15]) {
		t.Fatalf("skip_hash=true 内容不正确: %v %q", err, part)
	}

	// 尾部块 + skip_hash：eof 仍按 offset+length 判定。
	tail := artifactReadOf(t, sb, map[string]any{
		"action": "read", "workspace": "skiphash", "path": "c.txt",
		"offset": int64(len(content) - 3), "length": 100, "skip_hash": true,
	})
	if tail.SHA256 != "" || !tail.EOF || tail.Length != 3 {
		t.Fatalf("尾部 skip_hash 行为错误: %+v", tail)
	}
	if part, err := base64.StdEncoding.DecodeString(tail.Base64); err != nil || !bytes.Equal(part, content[len(content)-3:]) {
		t.Fatalf("尾部 skip_hash 内容不正确: %v %q", err, part)
	}
}

// 超大文件不哈希（避免 manifest 变成一次全量读盘），但大小仍要计入并给出 warning。
func TestArtifactsManifestOversizeWarning(t *testing.T) {
	sb := newTestSandbox(t)
	sb.artifactHashLimit = 4 // 测试注入小阈值
	ws, err := sb.workspace("big")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "small.txt"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "large.bin"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := artifactManifestOf(t, sb, "big")
	got := map[string]artifactFile{}
	for _, f := range m.Files {
		got[f.Path] = f
	}
	if got["large.bin"].SHA256 != "skipped:too-large" || got["large.bin"].Size != 10 {
		t.Fatalf("超大文件应保留 size、sha256 为 skipped:too-large: %+v", got["large.bin"])
	}
	if got["small.txt"].SHA256 != shaOf([]byte("abc")) {
		t.Fatalf("小文件应正常哈希: %+v", got["small.txt"])
	}
	if m.TotalBytes != 13 {
		t.Fatalf("超大文件的大小仍应计入 total_bytes: %d", m.TotalBytes)
	}
	if len(m.Warnings) != 1 || !strings.Contains(m.Warnings[0], "large.bin") || !strings.Contains(m.Warnings[0], "skipped") && !strings.Contains(m.Warnings[0], "sha256") {
		t.Fatalf("应有一条针对 large.bin 的 warning: %+v", m.Warnings)
	}
}

// 条目上限：按路径排序后截断，并说明截断了多少。
func TestArtifactsManifestEntryCap(t *testing.T) {
	sb := newTestSandbox(t)
	sb.artifactMaxEntries = 3
	ws, err := sb.workspace("cap")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"e.txt", "a.txt", "d.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(ws, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := artifactManifestOf(t, sb, "cap")
	if m.FilesCount != 3 || len(m.Files) != 3 {
		t.Fatalf("超过上限应按 3 条截断: %+v", m.Files)
	}
	var paths []string
	for _, f := range m.Files {
		paths = append(paths, f.Path)
	}
	if strings.Join(paths, ",") != "a.txt,b.txt,c.txt" {
		t.Fatalf("应按路径排序后截断，实际 %v", paths)
	}
	if len(m.Warnings) != 1 || !strings.Contains(m.Warnings[0], "5") || !strings.Contains(m.Warnings[0], "3") {
		t.Fatalf("应说明总数与上限: %+v", m.Warnings)
	}
}

// 两个 action 都必须走 resolveInWorkspace：工作区外的东西一概读不到。
func TestArtifactsRejectsOutsidePaths(t *testing.T) {
	sb := newTestSandbox(t)
	ws, err := sb.workspace("confined")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sb.Root, "secret.txt"), []byte("root-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../secret.txt", "../../etc/passwd", "/etc/passwd", "~/secret.txt", "dir/../../secret.txt"} {
		if _, err := call(t, sb, "artifacts", map[string]any{
			"action": "read", "workspace": "confined", "path": bad,
		}); err == nil {
			t.Fatalf("越界路径 %q 应被拒绝", bad)
		}
	}
	if _, err := call(t, sb, "artifacts", map[string]any{
		"action": "read", "workspace": "confined", "path": "dir",
	}); err == nil {
		t.Fatal("目录不应被 read 接受")
	}
	if _, err := call(t, sb, "artifacts", map[string]any{
		"action": "read", "workspace": "confined",
	}); err == nil {
		t.Fatal("action=read 缺少 path 应报错")
	}
	if _, err := call(t, sb, "artifacts", map[string]any{
		"action": "nope", "workspace": "confined",
	}); err == nil {
		t.Fatal("未知 action 应报错")
	}
}

// 工具必须注册进 MCP 工具表，否则控制面根本发现不到它。
func TestArtifactsRegisteredInToolList(t *testing.T) {
	sb := newTestSandbox(t)
	tool, ok := sb.byName["artifacts"]
	if !ok {
		t.Fatal("artifacts 未注册")
	}
	props, _ := tool.Schema["properties"].(map[string]any)
	for _, want := range []string{"action", "workspace", "path", "offset", "length"} {
		if _, ok := props[want]; !ok {
			t.Fatalf("schema 缺少 %s: %+v", want, props)
		}
	}
}
