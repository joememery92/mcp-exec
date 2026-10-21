// mcpnode：远程执行端 MCP 服务。
//
// 用法（节点，systemd 拉起）：
//
//	mcpnode -addr 127.0.0.1:18787 -root /var/lib/mcpnode/ws \
//	    -token-file /etc/mcpnode/token \
//	    -proxy http://127.0.0.1:18788 -ca /etc/mcpnode/recording-ca.pem
//
// 只监听回环：外部访问一律经控制端发起的 SSH 反向隧道（本机 ssh -R），
// 因此节点不需要开放任何入站端口，被扫到也没有服务。容器形态
// （容器形态）反过来绑 0.0.0.0 + 开一个入站端口，此时令牌是唯一
// 的门；没有令牌时启动日志会明确警告。
//
// 容器形态（无 SSH、可能没有公网入站）多一件事：-announce，启动成功后把「我是谁、
// MCP 在哪」自报给控制端，之后每 5 分钟重复（换 IP/换隧道能自我更新），见 announce.go。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/joememery92/mcp-exec/internal/mcp"
	"github.com/joememery92/mcp-exec/internal/recording"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18787", "监听地址（节点绑 127.0.0.1:18787；容器形态绑 0.0.0.0:18787）")
	root := flag.String("root", "/var/lib/mcpnode/ws", "工作区根目录")
	home := flag.String("home", "", "命令的 HOME（默认：$HOME，root 时用 /root）")
	token := flag.String("token", "", "调用令牌（也可用 -token-file / 环境变量 MCPNODE_TOKEN）")
	tokenFile := flag.String("token-file", "", "从文件读取令牌")
	proxy := flag.String("proxy", "", "录制代理，如 http://127.0.0.1:18788")
	ca := flag.String("ca", "", "录制代理 CA 证书路径")
	record := flag.String("record", "", "本地录制目录（空=不录；给了就在节点内起一个录制代理，复用 traffic 包）")
	recordAddr := flag.String("record-addr", "127.0.0.1:18788", "本地录制代理监听地址")
	recordKeep := flag.Duration("record-keep", 168*time.Hour, "本地录制保留期（超期行每小时清理一次；0 = 不清理）")
	egress := flag.String("egress-ip", "", "对外 IP（仅用于环境卡展示）")
	announce := flag.String("announce", "", "控制端地址，开启节点自报（如 http://127.0.0.1:8787）")
	announceName := flag.String("announce-name", "", "自报的节点名（[a-z0-9-]+；默认取主机名）")
	announceToken := flag.String("announce-token", "", "注册令牌（也可用 -announce-token-file；见控制端 控制端注册令牌接口）")
	announceTokenFile := flag.String("announce-token-file", "", "从文件读取注册令牌")
	announceURL := flag.String("announce-url", "", "本节点对外可达的 MCP 地址（缺省：出口 IP + 监听端口）")
	announceLabels := flag.String("announce-labels", "", "自报能力标签，逗号分隔（recon,ad,...）")
	maxSync := flag.Duration("max-sync", 300*time.Second, "同步 bash 上限")
	maxAsync := flag.Duration("max-async", 30*time.Minute, "后台任务上限")
	showVersion := flag.Bool("version", false, "打印版本")
	flag.Parse()

	if *showVersion {
		fmt.Println("mcpnode", mcp.Version)
		return
	}

	// 令牌优先级：flag > 文件 > 环境变量
	tok := strings.TrimSpace(*token)
	if tok == "" && *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("[mcpnode] 读取令牌文件失败: %v", err)
		}
		tok = strings.TrimSpace(string(data))
	}
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("MCPNODE_TOKEN"))
	}
	if tok == "" {
		log.Printf("[mcpnode] 警告：未配置令牌，任何能访问 %s 的进程都能调工具", *addr)
	}
	// 监听地址决定暴露面。节点形态只绑回环（外部一律经 SSH 隧道）；容器形态必须绑
	// 0.0.0.0，"对外可达"是设计的一部分——所以这里按「有没有令牌」分级：没令牌才是
	// 危险，有令牌只是提示。
	if !loopbackListen(*addr) {
		if tok == "" {
			log.Printf("[mcpnode] 警告：监听 %s 不在回环上，且没有令牌——任何能访问它的人都能执行命令", *addr)
		} else {
			log.Printf("[mcpnode] 提示：监听 %s 不在回环上（容器形态正常），调用需要 Bearer 令牌", *addr)
		}
	}

	if err := os.MkdirAll(*root, 0o755); err != nil {
		log.Fatalf("[mcpnode] 创建工作区根失败: %v", err)
	}

	// HOME 的解析顺序：显式参数 > 进程 $HOME > root 用 /root > 状态目录下的 home。
	// 不能留空：ProjectDiscovery 工具会因此把缓存建到工作区，并找不到 nuclei 模板。
	resolvedHome := strings.TrimSpace(*home)
	if resolvedHome == "" {
		resolvedHome = strings.TrimSpace(os.Getenv("HOME"))
	}
	if resolvedHome == "" && os.Geteuid() == 0 {
		resolvedHome = "/root"
	}
	if resolvedHome == "" {
		resolvedHome = filepath.Join(filepath.Dir(*root), "home")
	}
	if err := os.MkdirAll(resolvedHome, 0o755); err != nil {
		log.Printf("[mcpnode] 创建 HOME(%s) 失败，回落为空: %v", resolvedHome, err)
		resolvedHome = ""
	}

	sb := mcp.New(*root)
	sb.Home = resolvedHome
	sb.Token = tok
	sb.Proxy = strings.TrimSpace(*proxy)
	sb.CACert = strings.TrimSpace(*ca)
	sb.EgressIP = strings.TrimSpace(*egress)
	sb.MaxSync = *maxSync
	sb.MaxAsync = *maxAsync

	// 节点自带录制器：控制端在 NAT 后面、没有公网入站，节点无法把流量"推"回去，
	// 只能由平台出站拉。录制先落在节点本地，再由 traffic_export + artifacts 拉取。
	// -record 给出时本地录制器才是第一跳，-proxy（指向别的录制代理）被覆盖：
	// 两个上层代理串联没有意义，而且节点也连不到控制端的 8788。
	var recorder *recording.Traffic
	if dir := strings.TrimSpace(*record); dir != "" {
		if strings.TrimSpace(*proxy) != "" {
			log.Printf("[mcpnode] 已给 -record，忽略 -proxy %s（流量先经本地录制器 %s）", *proxy, *recordAddr)
		}
		tr, err := recording.Open(dir, strings.TrimSpace(*recordAddr))
		if err != nil {
			log.Fatalf("[mcpnode] 打开本地录制器失败: %v", err)
		}
		go func() {
			if err := tr.Start(); err != nil {
				log.Printf("[mcpnode] 本地录制代理退出: %v", err)
			}
		}()
		// Start 是阻塞调用、绑定失败只会在 goroutine 里变成一行日志，那等于「说录了其实没录」。
		// 起完探一次监听：端口被占用时直接退出，而不是带着一个假录制器继续跑。
		if !waitListening(strings.TrimSpace(*recordAddr), 5*time.Second) {
			log.Fatalf("[mcpnode] 录制代理未能在 %s 监听（端口被占用？）", *recordAddr)
		}
		recorder = tr
		sb.Traffic = tr
		sb.Proxy = "http://" + strings.TrimSpace(*recordAddr)
		if strings.TrimSpace(*ca) == "" {
			// 证书由录制器首次启动时生成在同一目录下；显式 -ca 优先，用于节点上
			// 已经有一份受信 CA 的部署。
			sb.CACert = tr.CACertPath()
		}
		// 录制库只增不减会撑爆节点盘：节点不像控制端那样有 平台的 gc 定时器，
		// 所以清理放在沙箱自己身上——每小时删一次超期行并 checkpoint WAL。
		if *recordKeep > 0 {
			go pruneRecorder(tr, *recordKeep)
		}
		log.Printf("[mcpnode] 本地录制器: %s | 录制目录 %s | 代理 %s | CA %s",
			*recordAddr, dir, sb.Proxy, orDash(sb.CACert))
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           sb.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 先显式绑定端口再起自报：自报的含义是"控制端现在能连到我了"，所以在监听就绪
	// 之后才发出去，控制端拿到就能立刻探活（而不是拿到一个连不上的地址）。
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("[mcpnode] 监听 %s 失败: %v", *addr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Printf("[mcpnode] 收到退出信号，停止监听")
		cancel()
		_ = srv.Close()
	}()

	log.Printf("[mcpnode] 启动: %s | 工作区 %s | HOME %s | 代理 %s | 令牌 %s",
		*addr, *root, orDash(resolvedHome), orDash(sb.Proxy), tokenState(tok))

	annCfg, annErr := announceConfigFromFlags(*announce, *announceName, *announceToken, *announceTokenFile, *announceURL, *announceLabels)
	if annErr != "" {
		log.Printf("[mcpnode] %s", annErr)
	}
	if annCfg != nil {
		annCfg.SandboxToken = tok
		log.Printf("[mcpnode] 节点自报已开启: 控制端 %s，节点名 %s，对外地址 %s（每 %v 一次）",
			annCfg.ControlURL, annCfg.Name, orDash(annCfg.MCPURL), announceInterval)
		go newAnnouncer(*annCfg, *addr).run(ctx)
	}

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[mcpnode] 退出: %v", err)
	}
	if recorder != nil {
		// 显式 checkpoint 再 Close：Close 只关 sqlite 连接，WAL 里的已提交帧虽然
		// 会随连接关闭落盘，但一次 TRUNCATE 能把它们合并回主库，节点下次导出前
		// 不会被一个巨大的 WAL 拖慢。
		if _, err := recorder.DB().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			log.Printf("[mcpnode] 录制库 checkpoint 失败: %v", err)
		}
		if err := recorder.Close(); err != nil {
			log.Printf("[mcpnode] 关闭录制器失败: %v", err)
		}
	}
}

// waitListening 轮询一个地址直到可连接或超时，用于确认录制代理真的起来了。
func waitListening(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// loopbackListen 判断监听地址是否只绑回环（节点形态的预期值）。
func loopbackListen(addr string) bool {
	for _, prefix := range []string{"127.0.0.1:", "localhost:", "[::1]:"} {
		if strings.HasPrefix(addr, prefix) {
			return true
		}
	}
	return false
}

func tokenState(tok string) string {
	if tok == "" {
		return "未设置"
	}
	return fmt.Sprintf("已设置(%d 字节)", len(tok))
}

func orDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// pruneRecorder 每小时清理一次节点本地录制库里超过保留期的行。
// 只删 exchanges/正文，不碰 _ca 与索引文件本身；清理后 checkpoint WAL，
// 让「删了但没还盘」的空间真正回到文件系统（控制端那边踩过同一个坑）。
func pruneRecorder(tr *recording.Traffic, keep time.Duration) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		cutoff := time.Now().Add(-keep)
		n, err := tr.DeleteBefore(cutoff)
		switch {
		case err != nil:
			log.Printf("[mcpnode] 录制库清理失败（保留 %s）: %v", keep, err)
		case n > 0:
			if _, cerr := tr.DB().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); cerr != nil {
				log.Printf("[mcpnode] 录制库清理后 checkpoint 失败: %v", cerr)
			}
			log.Printf("[mcpnode] 录制库清理：删除 %d 条早于 %s 的记录", n, cutoff.Format(time.RFC3339))
		}
		<-tick.C
	}
}
