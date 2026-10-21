package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joememery92/mcp-exec/internal/recording"
)

func TestTrafficExportRequiresRecorder(t *testing.T) {
	sb := New(t.TempDir())
	if _, err := sb.byName["traffic_export"].Call(context.Background(), map[string]any{"workspace": "w"}); err == nil {
		t.Fatal("traffic_export must fail when no recorder is configured")
	}
}

func TestTrafficExportWritesImportableArchive(t *testing.T) {
	rec, err := recording.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	now := time.Now().Unix()
	for i, ts := range []int64{now - 60, now - 30} {
		id := []string{"e1", "e2"}[i]
		if _, err := rec.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`, id, ts, "node.example", "GET", "/p", "https://node.example/p", 200, "text/plain", 0, 4); err != nil {
			t.Fatal(err)
		}
		if _, err := rec.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body)
VALUES(?,?,?,?,?)`, id, "GET /p HTTP/1.1", nil, "HTTP/1.1 200 OK", []byte("resp")); err != nil {
			t.Fatal(err)
		}
	}

	root := t.TempDir()
	sb := New(root)
	sb.Traffic = rec
	// compress=false 时目录保留，测试能直接检查导出物本身。
	out, err := sb.byName["traffic_export"].Call(context.Background(), map[string]any{
		"workspace": "traffic-sync",
		"since":     time.Unix(now-3600, 0).UTC().Format(time.RFC3339),
		"until":     time.Unix(now, 0).UTC().Format(time.RFC3339),
		"limit":     10,
		"compress":  false,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		OK        bool     `json:"ok"`
		Dir       string   `json:"dir"`
		Archive   string   `json:"archive"`
		Exchanges int      `json:"exchanges"`
		Files     []string `json:"files"`
		Truncated bool     `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("bad tool JSON %q: %v", out, err)
	}
	// 目录名带时间戳：定时器与手工触发撞在一起时两份导出互不覆盖。
	if !got.OK || got.Exchanges != 2 || !strings.HasPrefix(got.Dir, "traffic-export-") || got.Truncated || got.Archive != "" {
		t.Fatalf("tool result = %+v", got)
	}
	exportDir := filepath.Join(root, "traffic-sync", got.Dir)
	if _, err := os.Stat(filepath.Join(exportDir, "recording.json")); err != nil {
		t.Fatalf("archive manifest missing: %v", err)
	}

	// 再导一次：新目录（同一秒内可能同名，但绝不会覆盖已有内容）。
	if _, err := sb.byName["traffic_export"].Call(context.Background(), map[string]any{
		"workspace": "traffic-sync",
		"since":     time.Unix(now-40, 0).UTC().Format(time.RFC3339),
		"until":     time.Unix(now, 0).UTC().Format(time.RFC3339),
		"compress":  false,
	}); err != nil {
		t.Fatal(err)
	}

	dst, err := recording.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	imported, err := dst.ImportArchive(exportDir)
	if err != nil || imported != 2 {
		t.Fatalf("imported=%d err=%v, want 2 rows from the first export", imported, err)
	}
}

// compress=true（默认）时导出物打成 tar.zst 并删掉目录，控制面只拉一个文件。
func TestTrafficExportCompressesByDefault(t *testing.T) {
	rec, err := recording.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	now := time.Now().Unix()
	if _, err := rec.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES('e1',?,'node.example','GET','/p','https://node.example/p',200,'text/plain',0,4,'')`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body)
VALUES('e1','GET /p HTTP/1.1',NULL,'HTTP/1.1 200 OK',?)`, []byte("resp")); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	sb := New(root)
	sb.Traffic = rec
	out, err := sb.byName["traffic_export"].Call(context.Background(), map[string]any{
		"workspace": "traffic-sync",
		"since":     time.Unix(now-3600, 0).UTC().Format(time.RFC3339),
		"until":     time.Unix(now, 0).UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Dir          string `json:"dir"`
		Archive      string `json:"archive"`
		ArchiveBytes int64  `json:"archive_bytes"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Archive != got.Dir+".tar.zst" || got.ArchiveBytes <= 0 {
		t.Fatalf("archive = %+v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "traffic-sync", got.Archive)); err != nil {
		t.Fatalf("archive file missing: %v", err)
	}
	// 目录已经删掉：只留一个可拉取文件，artifacts 清单不会把 blobs 一个个列出来。
	if _, err := os.Stat(filepath.Join(root, "traffic-sync", got.Dir)); !os.IsNotExist(err) {
		t.Fatalf("export dir should be gone after compression, stat err = %v", err)
	}
}
