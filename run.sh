#!/bin/sh
# OpenWrt / LuCI 批量登录检测 —— 前台快速启动（不需要 systemd / 不需要 root）
#
# 用法：
#   ./run.sh                 监听 0.0.0.0:5678
#   ./run.sh --port 8080     换端口
#   ./run.sh --host 127.0.0.1  只监听本机
#
# 需要长期后台常驻 / 开机自启，请用： sudo ./install.sh

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  echo "未找到 python3。请先安装：apt install python3 / yum install python3 / apk add python3"
  exit 1
fi

exec "$PY" "${DIR}/check.py" "$@"
