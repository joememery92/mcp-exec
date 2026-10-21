//go:build !windows

package mcp

import (
	"context"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// shellCommand 造一个带进程组隔离的 shell 命令：超时/终止时整组一起死，
// 否则扫描工具的孙子进程会成为孤儿，把节点的 CPU 与端口占住。
//
// 有意用非登录 shell（-c 而不是 -lc）：登录 shell 会 source /etc/profile.d/*，
// 那些脚本属于宿主的登录环境（实测有一台节点上 /etc/profile.d/resin-proxy.sh
// 是 bash 语法，dash 一读就炸，导致所有命令都失败）。执行端要的是干净、可预期的
// 命令环境，PATH 由 commandEnv 显式给出。
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// startSessionCmd 起一个常驻会话进程：独立进程组（终止时整组一起死），stdin 收成管道，
// stdout/stderr 交给同一个 Writer——交互式会话里两者的顺序就是人类看到的顺序。
//
// 有意不用 exec.CommandContext：会话的寿命由 close 与空闲回收决定，不该因为控制端
// 断开一次 HTTP 请求就被杀掉（那正是"常驻"要解决的问题）。
func startSessionCmd(shell, dir string, env []string, out io.Writer) (*exec.Cmd, io.WriteCloser, error) {
	cmd := exec.Command(shell)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
	// 会话必须是独立进程组：回收时杀整组，否则 shell 里启动的扫描器、REPL 子进程
	// 会变成孤儿把节点占住（与 shellCommand 同一条理由）。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		return nil, nil, err
	}
	return cmd, stdin, nil
}

// killSessionGroup 杀整个进程组；组已不存在时回落到杀进程本身。
func killSessionGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
