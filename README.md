# OpenWrt / LuCI 批量登录检测工具

对一批 OpenWrt / ImmortalWrt / iStoreOS 路由器批量验证「还能不能登录进去」。
**零第三方依赖**（纯 Python 标准库），单文件 `check.py` + 一个网页界面，默认监听 `0.0.0.0:5678`。

> 版本 `5.0-linux` · Python 3.9+ · 支持 Linux / macOS / 任何有 python3 的环境

---

## 一键下载并运行

```sh
curl -fsSL https://raw.githubusercontent.com/siqi7/openwrt-checker/master/get.sh | sh
```

跑完在浏览器打开 `http://<本机IP>:5678/` 即可（默认端口 5678，监听 0.0.0.0）。
文件会被放到 `~/.openwrt-checker/`，不需要 root。

### 装成 systemd 服务，开机自启（需要 root）

```sh
curl -fsSL https://raw.githubusercontent.com/siqi7/openwrt-checker/master/get.sh | sudo sh -s -- --install
```

服务名 `openwrt-checker`，安装目录 `/opt/openwrt-checker`。

### 一键脚本支持的参数

```sh
# 换端口
curl -fsSL .../get.sh | sh -s -- --port 8080

# 只监听本机（不对外暴露）
curl -fsSL .../get.sh | sh -s -- --host 127.0.0.1

# 装成服务并换端口
curl -fsSL .../get.sh | sudo sh -s -- --install --port 8080

# 用你自己的 fork / 分支
OPENWRT_CHECKER_REPO=you/repo OPENWRT_CHECKER_BRANCH=main \
  curl -fsSL .../get.sh | sh
```

`get.sh` 会先检查 `curl`/`wget` 和 `python3`，缺哪个就提示对应的安装命令，不会blindly往下跑。

---

## 它解决什么问题

老版本（v4）的判据是「页面里出现 `system` / `admin` / `网络` / `状态` 等关键词，**且**没有 `luci_username` 字段 → 判定登录成功」。
问题是：**登录页本身天然满足这个条件**——登录页有「网络/状态/管理」等导航文字，也没有 `luci_username` 字段。
结果就是「随便打开一个页面都被标成登录成功」。同时它对 CDN 的人机验证页也照单全收。

v5 改成**强证据判定**，只有下面三件事同时成立才算登录成功：

1. **拿到了会话 Cookie**，且名字以 `sysauth` 开头（`sysauth` / `sysauth_http`，精确前缀，不再用宽松的 `auth` 子串匹配）；
2. **带着这个 Cookie 重新访问受保护页面**（`/cgi-bin/luci/admin/status/overview`），**没有被重定向回登录页**；
3. 该页面返回 **200 且确实是一个 LuCI 页面**（结构与静态资源特征，不靠文案关键词）。

拿不到 Cookie、或者回访又被踢回登录页，就绝不会判成功。

### 判定矩阵

| 场景 | 判定 | 依据 |
| --- | --- | --- |
| 正确密码 + 能进后台 | ✅ 登录成功 | Cookie 前缀 `sysauth` + 受保护页可访问 |
| 密码错误 | ❌ 密码错误 | 无 Cookie / 结构上仍是登录页 |
| 根本不是登录页（如首页、报错页） | ⚠️ 不是 LuCI 登录页 | 结构特征不匹配 |
| 目标不可达 / 超时 | ❌ 连接失败 | 连接层异常 |
| HTTP Basic 认证设备 | ✅ 登录成功(Basic) | 401 → 带凭据重试 200 |
| 被 CDN 人机验证拦截 | ⚠️ 被 CDN 拦截 | 检测到 challenge 页，退避重试后仍失败 |

### 对 CDN 人机验证的处理

Cloudflare 等 CDN 会间歇性地把真实页面替换成 JS 挑战页（HTTP 403）。
工具会识别挑战页（`Cf-Mitigated` 头、`__cf_chl` / `challenge-platform` / `just a moment` 等特征），
然后**退避重试**（2s/4s/6s/8s），只有重试仍被拦截才明确报「被 CDN 人机验证拦截」——
不会再像以前那样把挑战页当成「不是 LuCI」而误判失败。

---

## 直接使用（不走一键脚本）

```sh
# 前台运行，默认 0.0.0.0:5678
python3 check.py

# 换端口 / 只听本机
python3 check.py --port 8080
python3 check.py --host 127.0.0.1

# 本地自测：内置 11 个模拟目标（真实 LuCI / 假 LuCI / 挑战页 / 错误密码 …），
# 不需要任何真实路由器，用来验证判定逻辑是否正确
python3 check.py --selftest

python3 check.py --version
```

也可以直接命令行批量检查（无界面）：

```sh
# 略，见网页界面里的「目标 / 用户名 / 密码」三列填写方式；
# 也支持 host:port 简写、http(s):// 完整地址、纯 IP。
```

---

## 目录结构

```
check.py                 主程序（零依赖，含 Web 界面 + 自测）
install.sh               安装为 systemd 服务（--dry-run 可预演）
run.sh                   前台快速启动
openwrt-checker.service  systemd unit 参考模板
get.sh                   一键下载并运行脚本
README.md                本文件
```

---

## 运维

```sh
# 查看日志
journalctl -u openwrt-checker -f

# 重启 / 停止 / 取消自启
systemctl restart openwrt-checker
systemctl stop openwrt-checker
systemctl disable openwrt-checker

# 卸载
sudo systemctl disable --now openwrt-checker
sudo rm /etc/systemd/system/openwrt-checker.service
sudo systemctl daemon-reload
```

没有 systemd 的环境（Alpine / OpenRC / 容器）可以用后台方式：

```sh
nohup python3 check.py --host 0.0.0.0 --port 5678 > checker.log 2>&1 &
# 停止：pkill -f check.py
```

---

## 兼容性

- **Python**：3.9 / 3.13 / 3.14 实测通过；`python3 -I -S`（禁用 site-packages）下仍 11/11 通过，证明零依赖。
- **固件**：OpenWrt / ImmortalWrt / iStoreOS 的 LuCI 登录页（`sysauth` 体系）通用；
  `sysauth_http` 变体同样识别；HTTP Basic 认证设备也能判定。
- **平台**：Linux（x86_64 / arm64 / mips 等只要有 python3）、macOS。

---

## 安全说明

- 所有请求都 **`trust_env=False`**，内网地址绝不会走系统代理。
- 不做任何「写入路由器」的操作，只读探测登录页与受保护页。
- 仓库内不含任何真实凭据。

## License

MIT
