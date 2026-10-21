//go:build windows

package mcp

import (
	"context"
	"io"
	"os/exec"
	"time"
)

// shellCommand 的 Windows 版本：仅用于本机开发时跑通编译与单元测试。
// 生产执行端是 Linux，进程组终止由 proc_unix.go 提供。
func shellCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "cmd", "/c", command)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// startSessionCmd 的 Windows 版本：仅用于本机开发时跑通编译与单元测试。
// Windows 没有 Setpgid 语义，回收只作用于会话进程本身。
func startSessionCmd(shell, dir string, env []string, out io.Writer) (*exec.Cmd, io.WriteCloser, error) {
	cmd := exec.Command(shell)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
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

func killSessionGroup(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
