# OpenWrt / LuCI 批量弱口令审计工具

对一批 OpenWrt / ImmortalWrt / iStoreOS 路由器批量验证「还能不能登录进去」，
用的是**固定的默认口令字典**——不需要你事先准备账号密码，跑完直接告诉你哪台设备的凭据是什么。
**零第三方依赖**（纯 Python 标准库），单文件 `check.py` + 一个网页界面，默认监听 `0.0.0.0:5678`。

> 版本 `5.2-linux` · Python 3.9+ · 支持 Linux / macOS / 任何有 python3 的环境

> ⚠️ **授权提醒**：本工具只应作用于**你自己拥有**、或**已获得书面授权**的设备。
> 它不是一个「破解」工具——只有一张 8 组的固定默认口令表，用途是找出**还在用出厂/默认口令**的设备。
> 未经授权对他人设备使用可能违反法律，并与 fail2ban 等防护机制冲突。

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

`get.sh` 会先检查 `curl`/`wget` 和 `python3`，缺哪个就提示对应的安装命令，不会 blindly 往下跑。

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

---

## 两阶段流水线：先探活，再审凭据

批量场景下最贵的是「对着死主机干等超时」。所以流程拆成两段：

```
阶段A · 探活（短超时 3s，高并发，便宜）
    ↓  只把「确认是 LuCI 登录页」的目标往下传
阶段B · 凭据审计（长超时 8s，贵，只有存活目标才跑）
    ↓
输出：命中账号密码 / 无需密码 / 全部未命中
```

- **阶段A** 只做一件事：目标上到底有没有活的 LuCI 登录页。连不通、超时、不是 LuCI 的，在这一步就被丢掉，
  不会再浪费 8 秒去做无意义的登录尝试。
- **阶段B** 才开始按字典顺序提交凭据，命中即停。绝大多数设备在第 1~3 组就能出结果，不会把 8 组全跑完。
- 界面上有一条实时状态行（`阶段A · 探活中 12/50` → `阶段B · 凭据审计 3/17`），能直接看出现在卡在哪一段。

两个超时都可以在界面上调（探活默认 3s，凭据默认 8s）。

---

## 弱口令字典（8 组，按命中率排序）

顺序 = 尝试顺序，命中即停：

| # | 账号 | 密码 | 说明 |
| --- | --- | --- | --- |
| 1 | `root` | *（空）* | OpenWrt 原生默认：root 且无密码 |
| 2 | `root` | `password` | 网上教程里最常见的一档 |
| 3 | `admin` | `admin` | 路由器通用出厂默认 |
| 4 | `root` | `root` | |
| 5 | `root` | `admin` | |
| 6 | `admin` | `password` | |
| 7 | `admin` | *（空）* | |
| 8 | `admin` | `root` | |

两种模式，界面上切换：

- **弱口令审计（默认）** —— 用上面 8 组自动跑，结果里直接列出**命中的账号密码**。
- **自定义凭据** —— 你指定单一账号密码，只测这一组（适合确认某台机器的特定凭据）。

结果表格里有一列 **「命中账号密码」**，命中的会写成 `root / (空密码)` 或 `admin / admin`；
「复制成功列表」按钮复制出来的内容也带凭据，可以直接粘进表格。
另外还有一种情况：**设备根本没开认证，直接进后台** —— 会单独标成「无需密码」。

---

## 判定矩阵

| 场景 | 判定 | 依据 |
| --- | --- | --- |
| 弱口令命中（如 root / 空密码） | ✅ 登录成功 + 列出凭据 | Cookie 前缀 `sysauth` + 受保护页可访问 |
| 设备未开认证，直接进后台 | ✅ 无需密码 | 受保护页本就返回后台内容 |
| 8 组全错 | ❌ 未命中 | 未取得 `sysauth*` 会话 |
| 自定义凭据正确 / 错误 | ✅ / ❌ | 同上 |
| 根本不是登录页（如首页、报错页） | ⚠️ 不是 LuCI 登录页 | 结构特征不匹配 |
| 目标不可达 / 超时 | ❌ 连接失败 | 阶段A 即被淘汰 |
| HTTP Basic 认证设备 | ✅ 登录成功(Basic) | 401 → 带凭据重试 200 |
| 被 CDN 人机验证拦截 | ⚠️ 被 CDN 拦截 | 检测到 challenge 页，退避重试后仍失败 |

### 对 CDN 人机验证的处理

Cloudflare 等 CDN 会间歇性地把真实页面替换成 JS 挑战页（HTTP 403）。
工具会识别挑战页（`Cf-Mitigated` 头、`__cf_chl` / `challenge-platform` / `just a moment` 等特征，
**且状态码属于 403 / 429 / 503**），然后**退避重试**（2s/4s/6s/8s），
只有重试仍被拦截才明确报「被 CDN 人机验证拦截」。

> 状态码闸门是必需的：`cf-error-details` 其实也出现在 Cloudflare 的**源站不可达错误页**（521/522/525 等）上，
> 早期把它当成挑战特征，导致 CF 后面挂掉的源站被当成挑战页狂重试 12 秒。现在只有 403/429/503 才当挑战。

---

## 性能：这一版为什么比 v5.0 更快

速度是 v5.2 的主要改动方向。核心是**砍掉每一次多余请求**，并用两阶段把超时代价挡住。

单目标请求数（真实基准，不是估算）：

| 场景 | 优化前 | 优化后 | 怎么省的 |
| --- | --- | --- | --- |
| 正确密码（表单登录） | 5 | **3** | 登录 POST 不再跟随 302（那个页面根本不用看）；回访验证从 2 次请求压到 1 次 |
| 弱口令命中 | — | **3** | 命中即停，2~8 组不会被跑完 |
| 自定义凭据命中 | 5 | **3** | 同上 |
| Basic Auth 设备 | 10 | **7** | 预计算 `Authorization` 头直接带上，不再走「先 401 再重发」的两轮握手 |
| 会话 Cookie 被改名的设备 | 7 | **4** | 回访候选路径短路退出 |
| 密码错误 | 2 | 2 | 已是下限 |
| 被 CDN 挑战（重试后成功） | 7 | **5** | 验证环节不再重复退避 |
| 死主机 / 黑洞地址 | 长 | **阶段A 3s 淘汰** | 不再用 8s 超时干等 |

另外两处关键修复：

- **验证环节不再退避重试。** 原来只有探测阶段关了挑战重试，`verify_session` 还开着，
  于是 4 条受保护页候选路径各退避一次，最坏能拖到 48 秒。现在验证阶段一次请求定生死。
- **密码错误时不再逐条解析失败原因。** 弱口令审计模式下失败是家常便饭，
  省掉每次失败的文案解析（7 次请求的代价），只在自定义凭据模式下才解析原因给你看。

死主机的 2×超时（http + https 各试一次）依然存在，但阶段A 用的是 3s，最坏 6s，且被并发吸收掉。

---

## 诊断模式：判定失败时，看到底卡在哪一关

它**不靠版本号判定**，靠的是 LuCI 的协议行为。所以碰到不认识的固件时，
你需要的不是"支持列表"，而是"卡在哪"。

勾上界面里的「诊断模式」，每个目标都会附一条逐步轨迹，结果里点「诊断 · N 步」展开，
「复制全部结果」也会把轨迹一并带上。轨迹长这样（真实目标，正确密码）：

```
[阶段A·探活] https://op.7117777.xyz
[候选地址] https://op.7117777.xyz
[阶段A] 探测 https://op.7117777.xyz
  GET  .../cgi-bin/luci/ -> HTTP 403  25945B  标题 "ImmortalWrt - LuCI"
  命中登录页：请求 /cgi-bin/luci/，实际落点 .../cgi-bin/luci/
  指纹 LuCI路径=是 luci-static=是 登录表单=是 LuCI标题=是
  识别到字段：用户名参数「luci_username」密码参数「luci_password」
[阶段A] 通过 https://op.7117777.xyz：是 LuCI 登录页
[阶段B] 第 1/8 组：root / (空密码)
[阶段二] 提交凭据 root / (空密码) 到 .../cgi-bin/luci/
  表单字段：用户名参数「luci_username」密码参数「luci_password」
  附带隐藏域：无
  POST .../cgi-bin/luci/ -> HTTP 200  28627B  标题 "ImmortalWrt - LuCI"
  登录响应 HTTP 200 -> /cgi-bin/luci/，sysauth* 会话 Cookie：sysauth_http
[阶段三] 带会话回访受保护页，确认登录态真的生效
  GET  .../admin/status/overview -> HTTP 200  28701B  标题 "ImmortalWrt - LuCI"
  受保护页 /cgi-bin/luci/admin/status/overview 确认已登录，会话真实有效
[结论] 登录成功 —— 登录成功（Cookie sysauth_http）
```

看不懂的固件，看这几行就够了：

- **阶段A跳过全部候选路径** → 目标不是 LuCI，或登录页不在标准路径（反代到子目录的会这样）
- **阶段A就报连接失败** → 死主机，根本没进凭据审计
- **阶段B试完 8 组都没拿到 `sysauth*` Cookie** → 不是弱口令，或该固件对密码做了前端加密（提交明文自然失败）
- **阶段三被弹回登录入口** → 认证过了但会话没建立起来，通常是 Cookie 名被魔改

同一个目标，非 LuCI 页面的诊断长这样——四条候选路径的落点和指纹一清二楚，止步于阶段A：

```
[阶段A] 探测 https://example.com
  GET  https://example.com/cgi-bin/luci/ -> HTTP 404  559B  标题 "Example Domain"
  GET  https://example.com/cgi-bin/luci  -> HTTP 404  559B  标题 "Example Domain"
  GET  https://example.com/luci/         -> HTTP 404  559B  标题 "Example Domain"
  GET  https://example.com/              -> HTTP 200  559B  标题 "Example Domain"
  跳过 /：指纹不达标 LuCI路径=否 luci-static=否 登录表单=否 LuCI标题=否
[结论] 失败 —— 未找到 LuCI 登录页
```

不开诊断模式时轨迹完全不记录，没有额外开销。诊断轨迹里**只记录字段名，不记录密码值**。

### 覆盖范围与已知边界

支持的是 **LuCI 这一套机制**，不是某几个版本号：

| 范围 | 情况 |
| --- | --- |
| OpenWrt 官方 18.06 – 25.12 | 兼容（LuCI2/JS 时代，机制未变） |
| ImmortalWrt / iStoreOS / Kwrt / LEDE | 兼容；ImmortalWrt 已真机实测 |
| uhttpd Basic Auth 模式 | 兼容（已测） |
| 12.09 – 17.01（LuCI1 时代） | 靠字段名语义兜底，理论兼容，**未真机验证** |
| 原厂固件 / 非 LuCI 面板 | 不适用，会如实报「未找到 LuCI 登录页」 |

已知会失败的几类（都不是版本问题，是"魔改"）：

1. **登录页不在标准路径** —— 只试 `/cgi-bin/luci/`、`/cgi-bin/luci`、`/luci/`、`/`，
   且要求最终 URL 落在 LuCI 路径下。反代到子目录（如 `http://host/router/`）会漏。
2. **前端加密密码的固件** —— 标准 LuCI 是明文 POST，工具也提交明文；做过哈希加盐的固件会失败。
3. **登录页有验证码 / 登录后强制二次验证**。
4. **会话 Cookie 被改名**（不用 `sysauth` 前缀）—— 概率很低，但会误报。
5. **批量检测触发 fail2ban / 限速** —— 弱口令审计会连续发若干次 POST，比单次探测更容易触发。
   表现为临时假失败，建议降并发或分批跑。
6. **设备只认强口令** —— 那 8 组字典本来就不该命中，会如实报「未命中」，这不是 bug。

自签 HTTPS 证书已经处理（关闭校验），裸地址会先试 http 再自动退到 https，这两点不用担心。

---

## 直接使用（不走一键脚本）

```sh
# 前台运行，默认 0.0.0.0:5678
python3 check.py

# 换端口 / 只听本机
python3 check.py --port 8080
python3 check.py --host 127.0.0.1

# 本地自测：内置 14 个模拟目标（真实 LuCI / 弱口令设备 / 免密设备 / 挑战页 / 强口令设备 …），
# 不需要任何真实路由器，用来验证「探活 + 弱口令审计」两阶段逻辑是否正确
python3 check.py --selftest

python3 check.py --version
```

目标列表的写法很宽松，三种都行：`192.168.1.1`、`192.168.1.1:8080`、`https://192.168.2.1:443`。
只写 IP 或 IP:端口时先试 http，连接失败再自动试 https。

`--selftest` 除了跑判定用例，还会打印一段完整的诊断轨迹样例
（用自定义主题改过字段名的固件做样本），可以直接看出诊断模式长什么样。

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

- **固件**：覆盖面与已知边界见上面「覆盖范围与已知边界」一节。
- **Python**：3.9 / 3.13 / 3.14 实测通过；`python3 -I -S`（禁用 site-packages）下仍 14/14 通过，
  证明确实零依赖。自测同时校验「14/14 用例通过」与「14/14 都产出诊断轨迹」。
- **平台**：Linux（x86_64 / arm64 / mips 等只要有 python3）、macOS。

---

## 安全说明

- 每个请求都挂 `ProxyHandler({})` 并清空代理环境，内网地址绝不会被系统代理劫持。
- 不做任何「写入路由器」的操作，只读探测登录页与受保护页。
- 密码只在内存中用于当次提交，不落盘、不写日志；诊断轨迹里**只记录字段名，不记录密码值**。
- 仓库内不含任何真实凭据。
- 请仅对你拥有或已获授权的设备使用；弱口令审计会短时间内发出多次登录尝试，注意目标侧的 fail2ban / 限速策略。

## License

MIT
