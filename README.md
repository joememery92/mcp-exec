# mcp-exec

一个自托管的 MCP 执行节点：把 `bash` / 长任务 / 常驻 shell / 文件读写 / 侦察 / 产物回传 / 流量导出
暴露成 MCP 工具，供任意 MCP 客户端远程调用。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/joememery92/mcp-exec/main/install.sh \
  | sudo bash -s -- --control-ip <允许访问的来源 IP>
```

安装脚本会自动完成：识别架构与 init（有 systemd 写单元，没有则生成 `start.sh` 用 nohup 启动）→
下载对应架构的二进制 → 生成令牌 → 写好配置 → 放行指定来源 IP → 启动并自检。

装完会打印：

```
 节点名   : mcpnode
 二进制   : /usr/local/bin/mcpnode (sha256…)
 监听     : 0.0.0.0:18787
 工作区   : /var/lib/mcpnode/ws
 MCP 地址 : http://<本机公网IP>:18787/mcp
 令牌     : <只打印一次>   ← 交给客户端
```

## 安装参数

| 参数 | 说明 |
|---|---|
| `--control-ip IP` | 只放行该来源访问服务端口，可重复；不给则不改防火墙 |
| `--listen ADDR` | 监听地址，默认 `0.0.0.0`；只给本机用就填 `127.0.0.1` |
| `--port N` | 端口，默认 `18787` |
| `--name NAME` | 节点名，决定二进制与配置目录名（默认 `mcpnode`） |
| `--workspace DIR` | 工作区根目录，默认 `/var/lib/<name>/ws` |
| `--token TOKEN` / `--token-file PATH` | 指定调用令牌；不给则自动生成并落 `/etc/<name>/token`（600） |
| `--record` / `--no-record` | 节点内本地录制（默认开，保留 168 小时，可 `--record-keep 72h`） |
| `--announce URL --announce-token T` | 启动后主动向控制端登记自己 |
| `--binary PATH\|URL` | 不走 Release，直接用本地或指定 URL 的二进制 |
| `--version TAG` | 指定 Release 版本，默认 `latest` |
| `--no-firewall` | 不改防火墙 |
| `--dry-run` | 只打印将要做的事 |
| `--uninstall` | 停服务并删除二进制与配置（保留工作区与录制数据） |

## 验证

```bash
curl http://127.0.0.1:18787/healthz
# {"ok":true,"running_jobs":0,"shell_sessions":0,"tools":18,...}

curl -s http://127.0.0.1:18787/mcp \
  -H "Authorization: Bearer $(cat /etc/mcpnode/token)" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## 端口与令牌

服务端口对来源不设限，鉴权只有 `Authorization: Bearer <令牌>` 一项：**令牌等于执行权**。
建议只用 `--control-ip` 放行固定来源，或把 `--listen` 收到内网/回环，并在云安全组上再做一次限制。
令牌轮换：改 `/etc/mcpnode/token` 后 `systemctl restart mcpnode`。

## 升级 / 卸载

```bash
# 升级（保留令牌与配置）
curl -fsSL https://raw.githubusercontent.com/joememery92/mcp-exec/main/install.sh | sudo bash -s -- --control-ip <IP>

# 卸载（保留 /var/lib/mcpnode 下的工作区与录制数据）
curl -fsSL https://raw.githubusercontent.com/joememery92/mcp-exec/main/install.sh | sudo bash -s -- --uninstall
```

## 许可证

AGPL-3.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
