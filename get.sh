#!/bin/sh
# OpenWrt / LuCI 批量登录检测 —— 一键下载并运行
#
# 直接用（前台运行，不需要 root，不需要装任何依赖）：
#   curl -fsSL https://raw.githubusercontent.com/siqi7/openwrt-checker/master/get.sh | sh
#
# 换端口 / 只听本机：
#   curl -fsSL .../get.sh | sh -s -- --port 8080
#   curl -fsSL .../get.sh | sh -s -- --host 127.0.0.1
#
# 装成 systemd 服务，开机自启（需要 root）：
#   curl -fsSL .../get.sh | sudo sh -s -- --install
#   curl -fsSL .../get.sh | sudo sh -s -- --install --port 8080
#
# 覆盖下载源（默认 siqi7/openwrt-checker 的 master 分支）：
#   OPENWRT_CHECKER_REPO=you/repo OPENWRT_CHECKER_BRANCH=main ... | sh

set -eu

REPO="${OPENWRT_CHECKER_REPO:-siqi7/openwrt-checker}"
BRANCH="${OPENWRT_CHECKER_BRANCH:-master}"
TARBALL="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"

INSTALL=0
ARGS=""
for a in "$@"; do
  case "$a" in
    --install) INSTALL=1 ;;
    -h|--help)
      sed -n '3,20p' "$0" 2>/dev/null || echo "用法见 https://github.com/${REPO}"
      exit 0 ;;
    *) ARGS="${ARGS} ${a}" ;;
  esac
done

if [ "$INSTALL" = "1" ]; then
  DEST="${OPENWRT_CHECKER_DIR:-/opt/openwrt-checker}"
else
  DEST="${OPENWRT_CHECKER_DIR:-$HOME/.openwrt-checker}"
fi

echo "=========================================="
echo "  OpenWrt / LuCI 批量登录检测"
echo "=========================================="
echo "  来源    ${REPO} (${BRANCH})"
echo "  安装到  ${DEST}"

# --- 找一个下载工具 --------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  DL="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  DL="wget -qO-"
else
  echo "[错误] 需要 curl 或 wget，两者都没有。" >&2
  echo "  Debian/Ubuntu : apt install -y curl" >&2
  echo "  RHEL/CentOS   : yum install -y curl" >&2
  echo "  Alpine        : apk add curl" >&2
  exit 1
fi

# --- 检查 python3 ---------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo "[错误] 未找到 python3，请先安装：" >&2
  echo "  Debian/Ubuntu : apt update && apt install -y python3" >&2
  echo "  RHEL/CentOS   : yum install -y python3" >&2
  echo "  Alpine        : apk add python3" >&2
  exit 1
fi

# --- 下载 -----------------------------------------------------------------
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t owc)"
trap 'rm -rf "$TMP"' EXIT INT TERM

echo
echo "下载中 ..."
if [ "$DL" = "curl -fsSL" ]; then
  curl -fsSL "$TARBALL" -o "$TMP/src.tar.gz"
else
  wget -qO "$TMP/src.tar.gz" "$TARBALL"
fi

tar -xzf "$TMP/src.tar.gz" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [ -z "$SRC" ] || [ ! -f "$SRC/check.py" ]; then
  echo "[错误] 解压后找不到 check.py，下载包可能不完整。" >&2
  exit 1
fi

mkdir -p "$DEST"
cp "$SRC/check.py" "$DEST/"
for f in install.sh run.sh openwrt-checker.service README.md; do
  [ -f "$SRC/$f" ] && cp "$SRC/$f" "$DEST/"
done
chmod +x "$DEST/check.py" 2>/dev/null || true
chmod +x "$DEST/install.sh" 2>/dev/null || true
chmod +x "$DEST/run.sh" 2>/dev/null || true

echo "已就位：$DEST"
echo

# --- 按模式执行 -----------------------------------------------------------
if [ "$INSTALL" = "1" ]; then
  cd "$DEST"
  # shellcheck disable=SC2086
  exec ./install.sh $ARGS
fi

# shellcheck disable=SC2086
exec "$DEST/run.sh" $ARGS
