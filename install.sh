#!/usr/bin/env bash
# MCP 执行节点一键部署
#
#   curl -fsSL https://raw.githubusercontent.com/joememery92/mcp-exec/main/install.sh \
#     | sudo bash -s -- --control-ip 203.0.113.9
#
# 做什么：识别环境（架构 / init / 防火墙 / 已有安装）→ 取二进制 → 建目录与令牌 →
# 写配置与 systemd 单元（没有 systemd 时退化为 nohup 启动）→ 放行控制端 → 起服务 → 自检。
# 重复执行安全：升级只换二进制、保留令牌与现有配置；显式给出的参数才覆盖。
#
#   --control-ip IP      允许访问本端口的控制端出口 IP，可重复
#   --name NAME          节点名（默认沿用已有安装，否则 mcpnode）
#   --port N             监听端口（默认 18787）
#   --listen ADDR        监听地址（默认 0.0.0.0；同机部署用 127.0.0.1）
#   --binary PATH|URL    用本地/远程二进制，跳过 GitHub 下载
#   --version TAG        GitHub Release 版本（默认 latest）
#   --repo OWNER/REPO    Release 所在仓库（默认见 DEFAULT_REPO）
#   --token TOKEN        调用令牌（默认沿用/生成）
#   --gh-token TOKEN     私有仓库的 GitHub 令牌（下载 Release 资产用；也可用 GITHUB_TOKEN 环境变量）
#   --token-file PATH    从文件读令牌
#   --workspace DIR      工作区根（默认 /var/lib/<name>/ws）
#   --record / --no-record   节点内本地录制（默认开，保留 168h）
#   --announce URL       控制端地址，开启节点自报（自动登记，无需手工添加）
#   --announce-token T   注册令牌（由控制端签发）
#   --labels L1,L2       能力标签（recon,ad,bash…）
#   --no-firewall        不改防火墙
#   --dry-run            只打印将要做的事
#   --uninstall          停服务并删除二进制/配置（保留工作区与录制数据）
set -euo pipefail

DEFAULT_REPO="joememery92/mcp-exec"

NAME="${MCPNODE_NAME:-}"
PORT=18787
LISTEN="0.0.0.0"
WORKSPACE=""
BINARY=""
VERSION="latest"
REPO=""
TOKEN=""
TOKEN_FILE_ARG=""
GH_TOKEN="${GITHUB_TOKEN:-}"
RECORD=1
RECORD_KEEP="168h"
ANNOUNCE=""
ANNOUNCE_TOKEN=""
ANNOUNCE_TOKEN_FILE=""
LABELS="bash"
CONTROL_IPS=()
FIREWALL=1
DRY=0
UNINSTALL=0
MAX_SYNC="300s"
MAX_ASYNC="30m"

say()  { printf '\033[36m[mcpnode]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[mcpnode]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[mcpnode]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY" = 1 ]; then printf '  + %s\n' "$*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --token-file) TOKEN_FILE_ARG="$2"; shift 2 ;;
    --gh-token) GH_TOKEN="$2"; shift 2 ;;
    --control-ip) CONTROL_IPS+=("$2"); shift 2 ;;
    --record) RECORD=1; shift ;;
    --no-record) RECORD=0; shift ;;
    --record-keep) RECORD_KEEP="$2"; shift 2 ;;
    --announce) ANNOUNCE="$2"; shift 2 ;;
    --announce-token) ANNOUNCE_TOKEN="$2"; shift 2 ;;
    --announce-token-file) ANNOUNCE_TOKEN_FILE="$2"; shift 2 ;;
    --labels) LABELS="$2"; shift 2 ;;
    --max-sync) MAX_SYNC="$2"; shift 2 ;;
    --max-async) MAX_ASYNC="$2"; shift 2 ;;
    --no-firewall) FIREWALL=0; shift ;;
    --dry-run) DRY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "未知参数：$1（--help 看用法）" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "需要 root（用 sudo 运行）"

# ── 环境识别 ────────────────────────────────────────────────────────────────
[ "$(uname -s)" = Linux ] || die "只支持 Linux（当前 $(uname -s)）"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l) die "32 位 ARM 无预编译包，请用 --binary 提供自编译二进制" ;;
  *) die "未知架构：$(uname -m)" ;;
esac

# 已有安装：从单元文件推断服务名，升级时不动别的配置。
detect_name() {
  local unit start bin
  for unit in /etc/systemd/system/*.service; do
    [ -f "$unit" ] || continue
    start=$(sed -n 's/^ExecStart=//p' "$unit" 2>/dev/null | head -1)
    case "$start" in */usr/local/bin/*) ;; *) continue ;; esac
    case "$start" in *-root*) ;; *) continue ;; esac
    bin=$(printf '%s' "$start" | awk '{print $1}')
    basename "$bin"
    return 0
  done
  pgrep -af -- '-root .*-token' 2>/dev/null | head -1 | awk '{print $2}' | xargs -r basename
}

if [ -z "$NAME" ]; then
  NAME="$(detect_name || true)"
  [ -n "$NAME" ] || NAME="mcpnode"
fi
case "$NAME" in *[!a-z0-9-]*) die "节点名只能用小写字母、数字与连字符：$NAME" ;; esac

BIN=/usr/local/bin/$NAME
CONF=/etc/$NAME
STATE=${WORKSPACE:-/var/lib/$NAME/ws}
RECORD_DIR=/var/lib/$NAME/traffic
TOKEN_FILE=$CONF/token
ENV_FILE=$CONF/mcpnode.env
START_SCRIPT=$CONF/start.sh
UNIT=/etc/systemd/system/$NAME.service

HAS_SYSTEMD=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then HAS_SYSTEMD=1; fi

MEM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
MEM_MAX=""; CPU_Q=""
if   [ "$MEM_MB" -lt 1500 ]; then MEM_MAX="800M"; CPU_Q="80%"
elif [ "$MEM_MB" -lt 4000 ]; then MEM_MAX="2G";   CPU_Q="90%"
fi

say "环境：$(uname -m) → $ARCH ｜ systemd=$HAS_SYSTEMD ｜ 内存 ${MEM_MB}MB ｜ 节点名 $NAME"

# ── 卸载 ────────────────────────────────────────────────────────────────────
if [ "$UNINSTALL" = 1 ]; then
  say "卸载 $NAME（保留 $STATE 与 $RECORD_DIR）"
  if [ "$HAS_SYSTEMD" = 1 ]; then
    run systemctl disable --now "$NAME" || true
    run rm -f "$UNIT"
    run systemctl daemon-reload
  else
    run pkill -f "$BIN" || true
  fi
  run rm -f "$BIN" "$ENV_FILE" "$TOKEN_FILE" "$START_SCRIPT"
  say "完成。工作区与录制数据仍在：rm -rf $STATE $RECORD_DIR $CONF"
  exit 0
fi

# ── 取二进制 ────────────────────────────────────────────────────────────────
[ -n "$REPO" ] || REPO="$DEFAULT_REPO"
ASSET="mcpnode-linux-$ARCH"

fetch() {
  # 私有仓库：Release 资产需要 Bearer 令牌，且会 302 到另一域名（必须 location-trusted）
  if command -v curl >/dev/null 2>&1; then
    if [ -n "${GH_TOKEN:-}" ]; then
      curl -fsSL --location-trusted --retry 3 -H "Authorization: Bearer $GH_TOKEN" -o "$2" "$1"
    else
      curl -fsSL --retry 3 -o "$2" "$1"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ -n "${GH_TOKEN:-}" ]; then
      wget -q --header="Authorization: Bearer $GH_TOKEN" -O "$2" "$1"
    else
      wget -qO "$2" "$1"
    fi
  else die "需要 curl 或 wget"; fi
}

# Release 资产：私有仓库 downloadable 地址会 404（302 到 objects 域名会丢鉴权），
# 因此令牌在场时直接回落到 API 下载（Accept: application/octet-stream）。
fetch_asset() { # repo version asset dest
  local repo="$1" ver="$2" name="$3" dest="$4" url
  if [ "$ver" = latest ]; then
    url="https://github.com/$repo/releases/latest/download/$name"
  else
    url="https://github.com/$repo/releases/download/$ver/$name"
  fi
  if fetch "$url" "$dest" 2>/dev/null; then return 0; fi
  [ -n "${GH_TOKEN:-}" ] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  GH_TOKEN="$GH_TOKEN" GH_REPO_SLUG="$repo" GH_VER="$ver" GH_ASSET="$name" GH_DEST="$dest" python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request

tok = os.environ["GH_TOKEN"]
repo, ver, asset = os.environ["GH_REPO_SLUG"], os.environ["GH_VER"], os.environ["GH_ASSET"]
dest = os.environ["GH_DEST"]
base = "https://api.github.com/repos/" + repo
hdr = {"Authorization": "Bearer " + tok, "User-Agent": "mcpnode-install"}


def get(url, accept):
    req = urllib.request.Request(url, headers={**hdr, "Accept": accept})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


rel = json.loads(get(base + ("/releases/latest" if ver == "latest" else "/releases/tags/" + ver),
                     "application/vnd.github+json"))
found = next((a for a in rel.get("assets", []) if a["name"] == asset), None)
if not found:
    print("Release 里没有 %s" % asset, file=sys.stderr)
    sys.exit(1)
data = get(base + "/releases/assets/%d" % found["id"], "application/octet-stream")
with open(dest, "wb") as f:
    f.write(data)
print("API 下载完成: %s (%d KB)" % (asset, len(data) // 1024))
PY
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SRC=""
case "$BINARY" in
  http://*|https://*)
    say "下载二进制：${BINARY%%\?*}"
    fetch "$BINARY" "$TMP/bin"; SRC="$TMP/bin" ;;
  "")
    say "下载 $ASSET：$REPO@$VERSION"
    fetch_asset "$REPO" "$VERSION" "$ASSET" "$TMP/bin" || die "下载失败：$ASSET（$REPO@$VERSION）
  私有仓库要加 --gh-token <token>（或 GITHUB_TOKEN），否则 Release 资产拿不到；
  没有 Release 也可用 --binary 指定本地二进制。"
    SRC="$TMP/bin" ;;
  *)
    [ -f "$BINARY" ] || die "二进制不存在：$BINARY"
    SRC="$BINARY" ;;
esac

chmod +x "$SRC" 2>/dev/null || true
if timeout 5 "$SRC" -version >"$TMP/ver.txt" 2>&1; then
  say "二进制版本：$(head -1 "$TMP/ver.txt")"
else
  warn "二进制没有回应 -version：确认它是 MCP 节点（继续安装）"
fi
BUILT_SHA=$(sha256sum "$SRC" | awk '{print $1}')
say "二进制 sha256=${BUILT_SHA:0:16}…"

# ── 令牌 ────────────────────────────────────────────────────────────────────
if [ -n "$TOKEN_FILE_ARG" ]; then
  [ -f "$TOKEN_FILE_ARG" ] || die "令牌文件不存在：$TOKEN_FILE_ARG"
  TOKEN=$(tr -d '\r\n' < "$TOKEN_FILE_ARG")
fi
if [ -z "$TOKEN" ] && [ -f "$TOKEN_FILE" ]; then
  TOKEN=$(tr -d '\r\n' < "$TOKEN_FILE")
fi
NEW_TOKEN=0
if [ -z "$TOKEN" ]; then
  TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-40)
  NEW_TOKEN=1
fi

# ── 目录与二进制 ────────────────────────────────────────────────────────────
say "目录与令牌"
run install -d -m 755 "$CONF" "$STATE"
[ "$RECORD" = 1 ] && run install -d -m 755 "$RECORD_DIR"
run install -m 755 "$SRC" "$BIN"

if [ "$DRY" = 1 ]; then
  printf '  + 写入 %s（600）\n  + 写入 %s（600）\n  + 写入 %s\n  + 写入 %s\n' \
    "$TOKEN_FILE" "$ENV_FILE" "$START_SCRIPT" "$([ "$HAS_SYSTEMD" = 1 ] && echo "$UNIT" || echo '(无 systemd，不写单元)')"
  say "dry-run 结束"
  exit 0
fi

umask 077
printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"

{
  echo "# 由 install.sh 生成；改完要 systemctl restart $NAME"
  echo "MCPNODE_ROOT=$STATE"
  echo "MCPNODE_HOME=/root"
  echo "MCPNODE_TOKEN_FILE=$TOKEN_FILE"
  echo "MCPNODE_MAX_SYNC=$MAX_SYNC"
  echo "MCPNODE_MAX_ASYNC=$MAX_ASYNC"
  if [ "$RECORD" = 1 ]; then
    echo "MCPNODE_RECORD=$RECORD_DIR"
    echo "MCPNODE_RECORD_KEEP=$RECORD_KEEP"
  fi
  if [ -n "$ANNOUNCE" ]; then
    echo "MCPNODE_ANNOUNCE=$ANNOUNCE"
    echo "MCPNODE_LABELS=$LABELS"
  fi
} > "$ENV_FILE"

if [ -n "$ANNOUNCE_TOKEN_FILE" ]; then
  [ -f "$ANNOUNCE_TOKEN_FILE" ] || die "注册令牌文件不存在：$ANNOUNCE_TOKEN_FILE"
  install -m 600 "$ANNOUNCE_TOKEN_FILE" "$CONF/enroll-token"
  echo "MCPNODE_ANNOUNCE_TOKEN_FILE=$CONF/enroll-token" >> "$ENV_FILE"
elif [ -n "$ANNOUNCE_TOKEN" ]; then
  printf '%s\n' "$ANNOUNCE_TOKEN" > "$CONF/enroll-token"
  chmod 600 "$CONF/enroll-token"
  echo "MCPNODE_ANNOUNCE_TOKEN_FILE=$CONF/enroll-token" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

# ── 启动脚本（有/无 systemd 共用；容器可直接当 entrypoint）──────────────────
cat > "$START_SCRIPT" <<START
#!/usr/bin/env bash
# 由 install.sh 生成
set -aeu
[ -f $ENV_FILE ] && { set -a; . $ENV_FILE; set +a; }
ARGS=(-addr '${LISTEN}:${PORT}' -root "\${MCPNODE_ROOT:-$STATE}" -home "\${MCPNODE_HOME:-/root}")
ARGS+=(-token-file "\${MCPNODE_TOKEN_FILE:-$TOKEN_FILE}")
ARGS+=(-max-sync "\${MCPNODE_MAX_SYNC:-$MAX_SYNC}" -max-async "\${MCPNODE_MAX_ASYNC:-$MAX_ASYNC}")
if [ -n "\${MCPNODE_RECORD:-}" ]; then
  ARGS+=(-record "\$MCPNODE_RECORD" -record-keep "\${MCPNODE_RECORD_KEEP:-168h}")
fi
if [ -n "\${MCPNODE_ANNOUNCE:-}" ]; then
  ARGS+=(-announce "\$MCPNODE_ANNOUNCE" -announce-name '$NAME')
  ARGS+=(-announce-labels "\${MCPNODE_LABELS:-bash}")
  [ -n "\${MCPNODE_ANNOUNCE_TOKEN_FILE:-}" ] && ARGS+=(-announce-token-file "\$MCPNODE_ANNOUNCE_TOKEN_FILE")
fi
exec $BIN "\${ARGS[@]}" "\$@"
START
chmod 755 "$START_SCRIPT"

# ── 服务 ────────────────────────────────────────────────────────────────────
if [ "$HAS_SYSTEMD" = 1 ]; then
  {
    echo '[Unit]'
    echo "Description=MCP execution node ($NAME)"
    echo 'After=network-online.target'
    echo 'Wants=network-online.target'
    echo
    echo '[Service]'
    echo 'Type=simple'
    echo "EnvironmentFile=$ENV_FILE"
    echo "ExecStart=$START_SCRIPT"
    echo 'Restart=always'
    echo 'RestartSec=3'
    echo 'LimitNOFILE=65535'
    if [ -n "$MEM_MAX" ]; then echo "MemoryMax=$MEM_MAX"; echo "CPUQuota=$CPU_Q"; fi
    echo
    echo '[Install]'
    echo 'WantedBy=multi-user.target'
  } > "$UNIT"
  systemctl daemon-reload
  systemctl enable "$NAME" >/dev/null 2>&1 || true
  systemctl restart "$NAME"
else
  warn "没有 systemd：生成 $START_SCRIPT（容器可直接作 entrypoint），用 nohup 常驻"
  : >"/var/log/$NAME.log"
  nohup "$START_SCRIPT" >>"/var/log/$NAME.log" 2>&1 &
fi

# ── 防火墙 ──────────────────────────────────────────────────────────────────
open_port() {
  local ip="$1" pos
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    ufw allow from "$ip" to any port "$PORT" proto tcp >/dev/null; return
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=$PORT protocol=tcp accept" >/dev/null
    firewall-cmd --reload >/dev/null; return
  fi
  if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
    nft add rule inet filter input ip saddr "$ip" tcp dport "$PORT" accept 2>/dev/null || true; return
  fi
  if command -v iptables >/dev/null 2>&1; then
    # 必须插在 REJECT/DROP 之前：-A 追加到末尾等于没写
    pos=$(iptables -L INPUT --line-numbers -n 2>/dev/null | awk '/REJECT|DROP/ {print $1; exit}')
    if [ -n "$pos" ]; then
      iptables -I INPUT "$pos" -p tcp --dport "$PORT" -s "$ip" -j ACCEPT
    else
      iptables -I INPUT 1 -p tcp --dport "$PORT" -s "$ip" -j ACCEPT
    fi
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    return
  fi
  warn "没识别到防火墙，跳过（云安全组仍需放行 $PORT/tcp）"
}

if [ "$FIREWALL" = 1 ]; then
  if [ ${#CONTROL_IPS[@]} -eq 0 ]; then
    warn "没给 --control-ip：不改防火墙（云安全组需自行放行 $PORT/tcp）"
  else
    for ip in "${CONTROL_IPS[@]}"; do
      say "放行 $ip → $PORT/tcp"
      open_port "$ip"
    done
  fi
fi

# ── 自检 ────────────────────────────────────────────────────────────────────
PROBE="http://127.0.0.1:$PORT"
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS -m 3 "$PROBE/healthz" >"$TMP/health.json" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
if [ "$ok" = 1 ]; then
  say "健康检查：$(cat "$TMP/health.json")"
else
  warn "健康检查未通过：journalctl -u $NAME -n 50（无 systemd 时看 /var/log/$NAME.log）"
fi

PUB_IP=$(curl -fsS -m 5 https://api.ipify.org 2>/dev/null || true)
MCP_URL="http://${PUB_IP:-<本机公网IP>}:$PORT/mcp"

echo
echo "────────────────────────────────────────────────────────"
printf ' 节点名   : %s\n' "$NAME"
printf ' 二进制   : %s (%s…)\n' "$BIN" "${BUILT_SHA:0:16}"
printf ' 监听     : %s:%s\n' "$LISTEN" "$PORT"
printf ' 工作区   : %s\n' "$STATE"
printf ' 录制     : %s\n' "$( [ "$RECORD" = 1 ] && echo "$RECORD_DIR（保留 $RECORD_KEEP）" || echo 关闭 )"
printf ' MCP 地址 : %s\n' "$MCP_URL"
if [ "$NEW_TOKEN" = 1 ]; then
  printf ' 令牌     : %s   ← 新生成，抄到控制端\n' "$TOKEN"
else
  printf ' 令牌     : 沿用 %s（未变更）\n' "$TOKEN_FILE"
fi
echo "────────────────────────────────────────────────────────"
echo " 控制端登记（二选一）："
echo "  1) 在控制端按「MCP 服务地址 + 令牌文件」登记这台节点："
echo "       URL   : $MCP_URL"
echo "       Token : $TOKEN_FILE"
echo "  2) 若控制端支持节点自报，重跑本脚本加 --announce <控制端地址> --announce-token <令牌>"
echo "            --announce http://<控制端>:8787 --announce-token <token>"
echo "────────────────────────────────────────────────────────"
