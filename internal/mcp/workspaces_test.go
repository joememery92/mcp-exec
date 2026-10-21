package mcp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 空工作区没有文件可看 mtime —— 必须回落到目录自身时间，否则 GC 会把"刚建的"
// 当成"很久以前"（零值时间），保留期形同虚设。
func TestCountTreeEmptyDirUsesDirMtime(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws-empty")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files, bytes, newest := countTree(dir)
	if files != 0 || bytes != 0 {
		t.Fatalf("空目录统计应为 0/0，得到 %d/%d", files, bytes)
	}
	if newest.IsZero() {
		t.Fatal("空目录应回落到目录自身 mtime，而不是零值")
	}
	if time.Since(newest) > time.Hour {
		t.Fatalf("目录 mtime 不合理: %s", newest)
	}
}

func TestCountTreeCountsFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "recon"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recon", "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, bytes, newest := countTree(dir)
	if files != 1 || bytes != 5 {
		t.Fatalf("统计错误: %d 个文件 %d 字节", files, bytes)
	}
	if newest.IsZero() {
		t.Fatal("mtime 不该为零值")
	}
}
