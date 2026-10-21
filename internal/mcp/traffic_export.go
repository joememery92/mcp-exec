package mcp

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// traffic_export：把节点本地录制器里的一段时间窗导出成控制端能直接 ImportArchive
// 的归档目录。控制端在 NAT 后面、没有公网入站，所以节点不能主动回传；平台作为 MCP
// 客户端出站拉取这条通路，是唯一不需要节点入站连接的方向。
const (
	trafficExportDirPrefix    = "traffic-export-"
	trafficExportDefaultLimit = 5000
	trafficExportMaxLimit     = 20000
	trafficExportDefaultSince = 24 * time.Hour
)

func (s *Sandbox) trafficExportTool() *Tool {
	return &Tool{
		Name: "traffic_export",
		Description: "把节点本地录制器（启动参数 -record）里的流量按时间窗导出成归档目录，供控制端拉取后 ImportArchive。\n" +
			"- workspace（必填）：导出目录写在该工作区下的 traffic-export/（recording.json + blobs/<sha256>.bin）；同名目录每次导出前整体重建，不会混入上一次的残留。\n" +
			"- since / until：RFC3339 时间，闭区间；since 默认最近 24 小时，until 默认现在。\n" +
			"- limit：最多导出多少条（按 ts 倒序，即最新的优先），默认 5000，上限 20000；" +
			"被截断时 ok=true 且 truncated=true。\n" +
			"- compress：默认 true，导完打成 <dir>.tar.zst 并删掉目录——录制正文多为 HTML/JS，压缩比通常 4–6 倍，跨机拉取快很多。\n" +
			"返回 {ok, workspace, dir, archive, exchanges, bytes, archive_bytes, since, until, truncated}；" +
			"dir/archive 都是工作区相对路径，控制端用 artifacts 按 archive 拉回并解压。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"workspace": map[string]any{"type": "string", "description": "工作区名（导出目录写在其下 traffic-export/）"},
				"since":     map[string]any{"type": "string", "description": "起始时间（RFC3339，含），默认 24 小时前"},
				"until":     map[string]any{"type": "string", "description": "结束时间（RFC3339，含），默认现在"},
				"limit":     map[string]any{"type": "number", "description": "最多导出的条数（最新优先），默认 5000，上限 20000"},
				"compress":  map[string]any{"type": "boolean", "description": "打成 tar.zst 再返回（默认 true）"},
			},
			"required": []string{"workspace"},
		},
		Call: func(_ context.Context, args map[string]any) (string, error) {
			if s.Traffic == nil {
				return "", fmt.Errorf("本沙箱没有本地录制器：启动时没有给 -record（或 -record 打开失败）")
			}
			ws, err := s.workspace(argString(args, "workspace"))
			if err != nil {
				return "", err
			}
			until := time.Now().UTC()
			if raw := strings.TrimSpace(argString(args, "until")); raw != "" {
				until, err = time.Parse(time.RFC3339, raw)
				if err != nil {
					return "", fmt.Errorf("until 不是 RFC3339 时间: %w", err)
				}
			}
			since := until.Add(-trafficExportDefaultSince)
			if raw := strings.TrimSpace(argString(args, "since")); raw != "" {
				since, err = time.Parse(time.RFC3339, raw)
				if err != nil {
					return "", fmt.Errorf("since 不是 RFC3339 时间: %w", err)
				}
			}
			if since.After(until) {
				return "", fmt.Errorf("时间范围非法: since(%s) 晚于 until(%s)", since.Format(time.RFC3339), until.Format(time.RFC3339))
			}
			limit := trafficExportDefaultLimit
			if v, ok := numericArg(args["limit"]); ok && v > 0 {
				limit = v
			}
			if limit > trafficExportMaxLimit {
				return "", fmt.Errorf("limit=%d 超过上限 %d", limit, trafficExportMaxLimit)
			}

			// 目录名带时间戳：定时器与手工触发撞在一起时，两份导出互不覆盖
			// （固定名会被后一次 RemoveAll 掉，正在拉取的那一轮直接读不到文件）。
			dirName := trafficExportDirPrefix + until.Format("20060102T150405Z") + "-" + randSuffix()
			dir := filepath.Join(ws, dirName)
			sweepOldExports(ws, 2*time.Hour)
			if err := os.RemoveAll(dir); err != nil {
				return "", fmt.Errorf("清理旧导出目录失败: %w", err)
			}
			report, err := s.Traffic.ExportRange(since.Unix(), until.Unix(), limit, dir)
			if err != nil {
				return "", fmt.Errorf("导出流量失败: %w", err)
			}
			compress := true
			if v, ok := args["compress"].(bool); ok {
				compress = v
			}
			archiveName := ""
			var archiveBytes int64
			if compress {
				archiveName = dirName + ".tar.zst"
				if err := packTarZst(dir, filepath.Join(ws, archiveName)); err != nil {
					return "", fmt.Errorf("打包导出目录失败: %w", err)
				}
				if fi, statErr := os.Stat(filepath.Join(ws, archiveName)); statErr == nil {
					archiveBytes = fi.Size()
				}
				if err := os.RemoveAll(dir); err != nil {
					return "", fmt.Errorf("打包后清理导出目录失败: %w", err)
				}
			}
			out, err := json.Marshal(map[string]any{
				"ok":            true,
				"workspace":     filepath.Base(ws),
				"dir":           dirName,
				"archive":       archiveName,
				"archive_bytes": archiveBytes,
				"exchanges":     report.Exchanges,
				"bytes":         report.Bytes,
				"since":         since.Format(time.RFC3339),
				"until":         until.Format(time.RFC3339),
				"truncated":     report.Truncated,
				"files":         report.Files,
			})
			if err != nil {
				return "", err
			}
			return string(out), nil
		},
	}
}

// sweepOldExports 清掉工作区里过期的导出物（目录或 tar.zst）。
// 导出目录只在「平台拉取失败、等下一轮重试」期间才有价值；超过 2 小时还没人拉，
// 说明那轮早失败了，留着只会把节点盘吃满。
func sweepOldExports(ws string, maxAge time.Duration) {
	entries, err := os.ReadDir(ws)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "traffic-export") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || time.Since(info.ModTime()) < maxAge {
			continue
		}
		_ = os.RemoveAll(filepath.Join(ws, name))
	}
}

// packTarZst 把整个目录打成 <dst> 的 tar.zst（标准 tar + zstd，控制端用 archive/tar
// 解开），写完再落盘校验大小，失败不留半截文件给下一轮拉取。
func packTarZst(srcDir, dst string) error {
	tmp := dst + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	zw, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(2))
	if err != nil {
		f.Close()
		return err
	}
	tw := tar.NewWriter(zw)
	base := filepath.Dir(srcDir)
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(base, path)
		if rerr != nil {
			return rerr
		}
		hdr, herr := tar.FileInfoHeader(info, "")
		if herr != nil {
			return herr
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		src, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer src.Close()
		_, cerr := io.Copy(tw, src)
		return cerr
	})
	if err != nil {
		tw.Close()
		zw.Close()
		f.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		zw.Close()
		f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// randSuffix 让同一秒内的两次导出也拿到不同目录名：导出目录是「这一轮拉取的凭据」，
// 撞名会让后一次 RemoveAll 掉前一次，正在拉取的那一轮直接读不到文件。
func randSuffix() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	}
	return hex.EncodeToString(b[:])
}
