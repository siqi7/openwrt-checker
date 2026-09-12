#!/bin/bash
# OpenWrt / LuCI 批量弱口令审计 —— Linux 一键安装为 systemd 服务
#
# 用法：
#   sudo ./install.sh              安装并立即启动（开机自启）
#   sudo ./install.sh --port 8080  指定端口，默认 5678
#   ./install.sh --dry-run         只打印将要写入的服务配置，不做任何改动
#
# 卸载：
#   sudo systemctl disable --now openwrt-checker
#   sudo rm /etc/systemd/system/openwrt-checker.service

set -u

SERVICE_NAME="openwrt-checker"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
PORT="${OPENWRT_CHECKER_PORT:-5678}"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:-5678}"; shift 2 ;;
    --port=*) PORT="${1#*=}"; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知参数：$1（用 --help 查看用法）"; exit 1 ;;
  esac
done

DIR="$(cd "$(dirname "$0")" && pwd)"
ENTRY="${DIR}/check.py"

echo "=========================================="
echo "  OpenWrt / LuCI 检测工具 —— systemd 安装"
echo "=========================================="
echo "  安装目录  ${DIR}"
echo "  监听端口  ${PORT}"
echo

# --- 1. 找 python3 ---------------------------------------------------------
PY=""
for cand in /usr/bin/python3 /usr/local/bin/python3 python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$(command -v "$cand")"; break; fi
done
if [ -z "$PY" ]; then
  echo "[错误] 未找到 python3。请先安装："
  echo "  Debian/Ubuntu : sudo apt update && sudo apt install -y python3"
  echo "  RHEL/CentOS   : sudo yum install -y python3"
  echo "  Alpine        : sudo apk add python3"
  exit 1
fi
echo "  Python    $($PY --version 2>&1)  ($PY)"

if [ ! -f "$ENTRY" ]; then
  echo "[错误] 找不到 $ENTRY，请确保 install.sh 与 check.py 在同一目录。"
  exit 1
fi
echo "  入口      $ENTRY"
echo

# --- 2. 生成 unit 内容 -----------------------------------------------------
UNIT_CONTENT="[Unit]
Description=OpenWrt / LuCI 批量弱口令审计 ${PORT}
Documentation=file://${DIR}/check.py
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DIR}
ExecStart=${PY} ${ENTRY} --host 0.0.0.0 --port ${PORT}
Restart=on-failure
RestartSec=3
# 日志进 journal：journalctl -u ${SERVICE_NAME} -f
StandardOutput=journal
StandardError=journal
KillSignal=SIGINT
TimeoutStopSec=10

# 基本加固：服务只需读写自己的工作目录
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"

if [ "$DRY_RUN" = "1" ]; then
  echo "---------- 将要写入 ${UNIT_PATH} ----------"
  printf '%s' "$UNIT_CONTENT"
  echo "------------------------------------------"
  echo "（--dry-run 模式，未做任何改动）"
  exit 0
fi

# --- 3. 权限检查 -----------------------------------------------------------
if [ "$(id -u)" != "0" ]; then
  echo "[错误] 安装 systemd 服务需要 root 权限，请用："
  echo "  sudo ./install.sh"
  exit 1
fi

# --- 4. 检查 systemd -------------------------------------------------------
if ! command -v systemctl >/dev/null 2>&1; then
  echo "[提示] 本机没有 systemd（可能是 Alpine / OpenRC / 容器环境）。"
  echo "       可以改用后台方式运行："
  echo
  echo "         cd ${DIR}"
  echo "         nohup ${PY} check.py --host 0.0.0.0 --port ${PORT} > checker.log 2>&1 &"
  echo
  echo "       停止：pkill -f 'check.py'"
  echo "       OpenRC 开机自启可自行写入 /etc/init.d/${SERVICE_NAME}"
  exit 1
fi

# --- 5. 端口占用检查 -------------------------------------------------------
if command -v ss >/dev/null 2>&1; then
  if ss -lntp 2>/dev/null | grep -q ":${PORT}[[:space:]]"; then
    echo "[警告] 端口 ${PORT} 当前已被占用："
    ss -lntp 2>/dev/null | grep ":${PORT}[[:space:]]"
    echo "       服务可能无法启动。可改用： sudo ./install.sh --port 8080"
    echo
  fi
fi

# --- 6. 写入并启动 ---------------------------------------------------------
echo "写入 ${UNIT_PATH} ..."
printf '%s' "$UNIT_CONTENT" > "$UNIT_PATH" || { echo "[错误] 写入失败"; exit 1; }

echo "重新加载 systemd 并启用服务 ..."
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}" || { echo "[错误] 启动失败"; exit 1; }

sleep 2
echo
systemctl --no-pager --full status "${SERVICE_NAME}" | head -20
echo

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$IP" ] && IP="<本机IP>"
echo "=========================================="
echo "  安装完成"
echo "=========================================="
echo "  访问地址   http://${IP}:${PORT}/"
echo "             http://127.0.0.1:${PORT}/"
echo "  查看日志   journalctl -u ${SERVICE_NAME} -f"
echo "  重启服务   systemctl restart ${SERVICE_NAME}"
echo "  停止服务   systemctl stop ${SERVICE_NAME}"
echo "  取消自启   systemctl disable ${SERVICE_NAME}"
echo "=========================================="
