#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenWrt / LuCI 批量登录检测工具 —— Linux 零依赖单文件版 (v5)

· 只用 Python 标准库：不需要 pip、不需要联网、不需要虚拟环境
· 默认监听 0.0.0.0:5678
· 判定原则：弱指纹只决定「值不值得尝试登录」，强证据决定「是否算成功」

成功必须同时满足三条：
  1) 会话 Cookie 名精确命中 sysauth*（不是子串匹配 "auth"）
  2) 带会话回访受保护页，未被 302 弹回登录入口
  3) 该页 200、不是登录页、且确实是 LuCI 页面
泛化关键词（system / admin / 网络 / 状态 …）一律不参与成败判定。

用法：
  python3 check.py                     监听 0.0.0.0:5678
  python3 check.py --port 8080         换端口
  python3 check.py --host 127.0.0.1    只监听本机
  python3 check.py --selftest           本地自测（不需要路由器）
"""

import argparse
import base64
import gzip
import http.cookiejar
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from http.server import ThreadingHTTPServer          # Python 3.7+
except ImportError:                                       # 兼容更老的 Python
    import socketserver

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

from urllib.parse import urlparse, urljoin, parse_qs

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5678
VERSION = "5.0-linux"

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# ---------------------------------------------------------------------------
# 指纹规则
# ---------------------------------------------------------------------------

# LuCI 会话 Cookie 名前缀。精确前缀匹配——除 LuCI 外没有系统用 sysauth 前缀，
# 因此不会像 v4 的 "auth" 子串那样把 oauth / auth_token / sso_auth 全放行。
SESSION_COOKIE_PREFIX = "sysauth"

# 明确的失败信号：只用于生成说明文字，不参与成败判定
FAIL_PATTERNS = [
    r"密码错误", r"密码不正确", r"用户名或密码", r"认证失败", r"登录失败", r"无效的密码",
    r"invalid\s+username\s+or\s+password",
    r"incorrect\s+(?:password|username)",
    r"authentication\s+failed",
    r"login\s+failed",
    r"wrong\s+password",
    r"invalid\s+credentials",
]

LUCI_TITLE_RE = re.compile(
    r"<(?:title|h1|h2)[^>]*>[^<]{0,120}?(luci|openwrt|istoreos|istore|immortalwrt|kwrt|lede)",
    re.I,
)

# Cloudflare / 人机验证 拦截页特征。
# 真实案例：目标挂在 Cloudflare 后面，会间歇性下发挑战页（HTTP 403 + 一段 JS）。
# 若不识别，就会把「被拦住」误判成「这不是 LuCI」，产生假失败。
CHALLENGE_PATTERNS = [
    r"__cf_chl",
    r"cf_chl_opt",
    r"challenge-platform",
    r"/cdn-cgi/challenge",
    r"just a moment",
    r"checking your browser",
    r"enable javascript and cookies to continue",
    r"attention required",
    r"cf-error-details",
    r'class="no-js ie6 oldie"',
]

CHALLENGE_RETRIES = 4          # 被挑战时重试次数
CHALLENGE_DELAY = 2.0          # 首次重试等待秒数，逐次递增（2s / 4s / 6s）

RE_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.I | re.S)
RE_ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>=`]+))""")
RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# 登录页候选路径
LOGIN_CANDIDATES = ["/cgi-bin/luci/", "/cgi-bin/luci", "/luci/", "/"]

# 受保护页候选路径，用于「带会话回访」验证
PROTECTED_CANDIDATES = [
    "/cgi-bin/luci/admin/status/overview",   # LuCI 21.02+ 默认首页
    "/cgi-bin/luci/admin/status",            # LuCI 19.07 及更早
    "/cgi-bin/luci/admin/",                  # 后台根路径
    "/cgi-bin/luci/",                        # 版本无关兜底（已登录时会被重定向到首页）
]


# ---------------------------------------------------------------------------
# HTML 解析工具
# ---------------------------------------------------------------------------

def parse_inputs(html):
    out = []
    for tag in RE_INPUT_TAG.findall(html):
        attrs = {}
        for m in RE_ATTR.finditer(tag):
            key = m.group(1).lower()
            val = m.group(2)
            if val is None:
                val = m.group(3)
            if val is None:
                val = m.group(4) or ""
            attrs[key] = val
        if attrs:
            out.append(attrs)
    return out


def find_login_fields(html):
    """
    定位登录表单字段名，返回 (用户名字段, 密码字段名)，无密码框则返回 None。
    优先精确识别 luci_username / luci_password；自定义主题改名后按 type/name 语义兜底。
    """
    inputs = parse_inputs(html)

    pwd_field = None
    for d in inputs:
        if d.get("type", "").lower() == "password" and d.get("name"):
            pwd_field = d["name"]
            break
    if not pwd_field:
        return None

    user_field = None
    for d in inputs:
        if d.get("name", "").lower() == "luci_username":
            user_field = d["name"]
            break
    if not user_field:
        for d in inputs:
            name = d.get("name", "")
            if not name:
                continue
            if d.get("type", "text").lower() not in ("text", "email", ""):
                continue
            if re.search(r"user|login|account|name", name, re.I):
                user_field = name
                break

    return (user_field, pwd_field)


def has_fail_signal(html):
    for p in FAIL_PATTERNS:
        if re.search(p, html, re.I):
            return True
    return False


def is_challenge_page(html, headers=None):
    """判断响应是不是 CDN / 人机验证 拦截页（而不是目标本身的页面）。"""
    if headers:
        for k in ("Cf-Mitigated", "X-Sucuri-Block"):
            if headers.get(k):
                return True
    h = html.lower()
    for p in CHALLENGE_PATTERNS:
        if re.search(p, h):
            return True
    return False


def page_title(html):
    m = RE_TITLE.search(html)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""


def fingerprint(html, final_url, html_l=None):
    """计算页面的 LuCI 指纹。只产出「证据」，不直接下成功结论。"""
    if html_l is None:
        html_l = html.lower()
    path = urlparse(final_url).path.lower()
    url_luci = ("/cgi-bin/luci" in path) or path.startswith("/luci/") or path == "/luci/"
    return {
        "url_luci": url_luci,
        "static_ref": "/luci-static/" in html_l,
        "login_form": find_login_fields(html) is not None,
        "title_luci": bool(LUCI_TITLE_RE.search(html)),
    }


def is_login_page(html):
    """
    判断页面是不是 LuCI 登录页（也就是「还没登录」）。

    刻意不使用任何文案关键词：LuCI 后台首页本身就可能出现「登录失败尝试」
    这类控件文案，用关键词判会把已登录的后台页误判成登录页。

    判据只基于结构：
      - 出现 LuCI 后端强制的字段名 luci_username / luci_password  -> 登录页
      - 有密码框但页面里没有任何后台入口特征(/cgi-bin/luci/admin 或 ;stok=) -> 登录页
      - 完全没有密码框 -> 不可能是登录页
    """
    h = html.lower()
    if "luci_password" in h or "luci_username" in h:
        return True
    if find_login_fields(html) is None:
        return False
    has_admin_marker = ("/cgi-bin/luci/admin" in h) or (";stok=" in h)
    return not has_admin_marker


def _is_login_entry(url):
    """最终 URL 是否停在 LuCI 登录入口。带 ;stok= 说明已建立会话，不算。"""
    path = urlparse(url).path
    if ";stok=" in path:
        return False
    path = re.sub(r";[^/]*", "", path).rstrip("/")
    return path in ("/cgi-bin/luci", "/luci", "")


def looks_like_luci_page(html, final_url):
    fp = fingerprint(html, final_url)
    if not fp["static_ref"]:
        return False
    return fp["url_luci"] or fp["title_luci"]


# ---------------------------------------------------------------------------
# HTTP 客户端（标准库实现）
# ---------------------------------------------------------------------------

class ConnectFailed(Exception):
    """连接层失败（端口不可达 / 超时），供上层决定是否换 scheme 重试。"""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不自动跟随跳转，把 3xx 原样交给调用方判断。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _decode_body(raw, headers):
    enc = (headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    elif "deflate" in enc:
        import zlib
        for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS):
            try:
                raw = zlib.decompress(raw, wbits)
                break
            except zlib.error:
                continue
    charset = None
    ctype = headers.get("Content-Type") or ""
    m = re.search(r"charset=([\w\-]+)", ctype, re.I)
    if m:
        charset = m.group(1)
    for cs in ([charset] if charset else []) + ["utf-8", "gb18030", "latin-1"]:
        try:
            return raw.decode(cs)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


class Session:
    """
    一个目标的探测会话。
    两个 opener 共享同一个 CookieJar，分别用于「跟随跳转」和「不跟随跳转」。

    注意：handler 实例不能跨 opener 复用。handler 被加入 opener 时会把自身的
    parent 指向该 opener，复用同一批实例会让先建的 opener 用上后建 opener 的配置，
    实测会退化成 "User-Agent: Python-urllib/3.x"，被 Cloudflare 直接判定为机器人
    并下发人机验证挑战页（403）。因此这里每个 opener 都用独立的新实例，
    并且所有请求头都在请求上显式给出，不依赖 opener.addheaders。
    """

    def __init__(self, timeout=8, basic_auth=None):
        self.timeout = timeout
        self._basic_auth = basic_auth
        self.jar = http.cookiejar.CookieJar()

        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

        self._follow = self._make_opener(no_redirect=False)
        self._nore = self._make_opener(no_redirect=True)

    def _make_opener(self, no_redirect):
        handlers = [
            urllib.request.ProxyHandler({}),   # 关键：内网地址不能走系统代理
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=self._ctx),
        ]
        if self._basic_auth:
            uri, user, pwd = self._basic_auth
            mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, uri, user, pwd)
            handlers.append(urllib.request.HTTPBasicAuthHandler(mgr))
        if no_redirect:
            handlers.insert(0, _NoRedirect())
        return urllib.request.build_opener(*handlers)

    def _raw(self, url, data=None, allow_redirects=True):
        opener = self._follow if allow_redirects else self._nore
        # 浏览器化的请求头，顺序也按浏览器习惯排列（部分 CDN 会看头部顺序）
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip",
        }
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST" if data is not None else "GET")
        try:
            resp = opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            resp = e            # 3xx(不跟随) / 4xx / 5xx 都当响应处理
        except urllib.error.URLError as e:
            raise ConnectFailed(str(e.reason))
        except (socket.timeout, TimeoutError):
            raise ConnectFailed("timeout")
        raw = resp.read()
        return {
            "status": resp.code,
            "url": resp.geturl(),
            "headers": resp.headers,
            "text": _decode_body(raw, resp.headers),
            "challenged": False,
        }

    def _do(self, url, data=None, allow_redirects=True, retry_challenge=True):
        """
        发起请求。若拿到 CDN 人机验证拦截页则退避重试——
        否则「被拦住」会被误判成「这不是 LuCI」，产生假失败。

        retry_challenge=False 用于代价较低的探测场景：挑战通常对所有路径一视同仁，
        在第一个规范路径上耐心等待即可，不必每条路径都撒请求。
        """
        attempts = CHALLENGE_RETRIES if retry_challenge else 1
        result = None
        for attempt in range(attempts):
            result = self._raw(url, data, allow_redirects)
            if not is_challenge_page(result["text"], result["headers"]):
                return result
            if attempt < attempts - 1:
                time.sleep(CHALLENGE_DELAY * (attempt + 1))
        result["challenged"] = True
        return result

    def get(self, url, allow_redirects=True, retry_challenge=True):
        return self._do(url, None, allow_redirects, retry_challenge)

    def post(self, url, data, allow_redirects=True, retry_challenge=True):
        return self._do(url, data, allow_redirects, retry_challenge)

    def session_cookies(self):
        return [c.name for c in self.jar if c.name.lower().startswith(SESSION_COOKIE_PREFIX)]


# ---------------------------------------------------------------------------
# 目标地址规整
# ---------------------------------------------------------------------------

def normalize_target(raw):
    """返回 (显示名, [候选 base_url])。裸地址先试 http，连接失败再试 https。"""
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        base = raw.rstrip("/")
        return base, [base]
    return raw, ["http://" + raw, "https://" + raw]


# ---------------------------------------------------------------------------
# 主检测逻辑
# ---------------------------------------------------------------------------

def _result(name, status, method, detail, evidence=""):
    return {"ip": name, "status": status, "method": method,
            "detail": detail, "evidence": evidence}


def probe_login_page(session, base):
    """
    阶段一：确认目标上跑的确实是 LuCI，并拿到登录页。
    返回 (probe, None) 表示找到；返回 (None, reason) 表示失败原因。
    reason 取值：'basic_auth' / 'connect' / 'challenge' / 'not_luci'

    注意：接受 HTTP 200 与 403。实测部分固件（ImmortalWrt + Cloudflare）
    把完整 LuCI 登录页以 403 下发，只认 200 会直接漏掉这类设备。
    """
    saw_401 = False
    saw_challenge = False
    connect_error = None

    for idx, path in enumerate(LOGIN_CANDIDATES):
        try:
            # 只在第一个规范路径上做退避重试：挑战对所有路径一视同仁，
            # 在规范路径上等它过去即可，避免对目标撒大量请求。
            r = session.get(base + path, allow_redirects=True,
                            retry_challenge=(idx == 0))
        except ConnectFailed as e:
            connect_error = e
            break

        if r.get("challenged"):
            saw_challenge = True
            continue
        if r["status"] == 401:
            saw_401 = True
            continue
        if r["status"] not in (200, 403):
            continue

        html = r["text"]
        if not html:
            continue
        html_l = html.lower()
        fp = fingerprint(html, r["url"], html_l)

        # 严格门禁：URL 必须落在 LuCI 路径下，且要么有登录表单，
        # 要么同时具备 luci-static 资源引用 + LuCI 系标题。
        if fp["url_luci"] and (fp["login_form"] or (fp["static_ref"] and fp["title_luci"])):
            return {"request_path": path, "login_url": r["url"],
                    "html": html, "fp": fp}, None

    if saw_401:
        return None, "basic_auth"
    if saw_challenge:
        return None, "challenge"
    if connect_error is not None:
        return None, "connect"
    return None, "not_luci"


def verify_session(session, base):
    """
    阶段三：带会话回访受保护页，确认真的进了后台。

    这是整个判定的关键——不看关键词、不看文案，只看「登录态是否真的生效」：
      1) 请求受保护页时不自动跟随跳转，先看是否被 302 弹回登录入口
      2) 跟随后最终 URL 若停在登录入口 -> 未登录
      3) 最终页面若仍是登录页 -> 未登录
      4) 必须是 200 且是 LuCI 页面 -> 才算真登录成功
    返回 (ok, detail, evidence)
    """
    tried = []
    for path in PROTECTED_CANDIDATES:
        url = base + path
        try:
            r = session.get(url, allow_redirects=False)
        except ConnectFailed:
            tried.append(path + ":请求异常")
            continue

        if r["status"] in (301, 302, 303, 307, 308):
            location = r["headers"].get("Location", "")
            try:
                r = session.get(urljoin(url, location), allow_redirects=True)
            except ConnectFailed:
                tried.append(path + ":跟随跳转异常")
                continue
            if _is_login_entry(r["url"]):
                tried.append(path + ":被弹回登录入口")
                continue

        if r["status"] != 200:
            tried.append("%s:HTTP %s" % (path, r["status"]))
            continue

        html = r["text"]
        if is_login_page(html):
            tried.append(path + ":仍是登录页")
            continue
        if not looks_like_luci_page(html, r["url"]):
            tried.append(path + ":非 LuCI 页面")
            continue

        return (True,
                "会话有效（%s 返回后台内容）" % path,
                "回访 %s 后返回后台内容，未弹回登录入口且无登录表单" % path)

    return False, "会话无效：受保护页仍要求登录", "回访失败：" + "；".join(tried[:3])


def try_login_and_verify(session, base, probe, username, password):
    """阶段二 + 三：提交登录并验证会话。成败只由「会话是否真的生效」决定。"""
    html = probe["html"]
    login_url = probe["login_url"]

    fields = find_login_fields(html)
    user_field, pwd_field = (fields if fields else (None, None))
    user_field = user_field or "luci_username"
    pwd_field = pwd_field or "luci_password"

    data = {}
    for d in parse_inputs(html):
        name = d.get("name", "")
        if name and d.get("type", "").lower() == "hidden":
            data[name] = d.get("value", "")

    data[user_field] = username
    data[pwd_field] = password
    # 自定义主题可能改过字段名，标准字段名一并提交（多余字段会被服务端忽略）
    data.setdefault("luci_username", username)
    data.setdefault("luci_password", password)

    try:
        resp = session.post(login_url, data, allow_redirects=True)
    except ConnectFailed as e:
        return False, "-", "登录请求异常：%s" % str(e)[:40], ""

    cookies = session.session_cookies()
    if cookies:
        ok, detail, evidence = verify_session(session, base)
        if ok:
            return True, "LuCI表单", "登录成功（Cookie %s）" % ",".join(cookies), evidence
        return False, "LuCI表单", detail, evidence

    # 没拿到 LuCI 会话凭据 —— 一定是失败。
    # 下面只决定「给人看的说明文案」，成败结论来自「没有会话」这个事实本身。
    # 优先用结构判据：登录后又被送回 LuCI 登录页，就是密码不对。
    # （实测某些固件认证失败时返回 HTTP 403 + 登录页，且页面上没有任何错误文案，
    #   只靠关键词会漏判，靠结构则稳定命中。）
    resp_fp = fingerprint(resp["text"], resp["url"])
    if is_login_page(resp["text"]) and resp_fp["static_ref"]:
        return False, "LuCI表单", "密码错误", "登录后仍回到 LuCI 登录页，且未下发 sysauth* Cookie"
    if has_fail_signal(resp["text"]):
        return False, "LuCI表单", "密码错误", "登录响应含明确的失败提示"
    return False, "LuCI表单", "未取得 LuCI 会话凭据", "响应未下发 sysauth* Cookie"


def try_basic_auth(base, username, password):
    """uhttpd Basic Auth 模式。凭据挂在 Session 上，回访验证的请求同样会带上。"""
    session = Session(basic_auth=(base, username, password))
    try:
        r = session.get(base + "/cgi-bin/luci/", allow_redirects=True)
    except ConnectFailed:
        return None
    if r["status"] == 401:
        return None

    cookies = session.session_cookies()
    if not cookies:
        return None

    ok, detail, evidence = verify_session(session, base)
    if ok:
        return "BasicAuth", "登录成功（Cookie %s）" % ",".join(cookies), evidence
    return None


def check_openwrt(raw, username, password, timeout=8):
    """检测单个目标。"""
    name, bases = normalize_target(raw)
    last = _result(name, "fail", "-", "未找到 LuCI 登录页")

    for base in bases:
        session = Session(timeout=timeout)
        probe, reason = probe_login_page(session, base)

        if probe is None:
            if reason == "basic_auth":
                got = try_basic_auth(base, username, password)
                if got:
                    method, detail, evidence = got
                    return _result(name, "success", method, detail, evidence)
                return _result(name, "fail", "BasicAuth", "Basic 认证失败",
                               "用户名或密码错误")
            if reason == "connect":
                last = _result(name, "fail", "-", "连接失败", "端口不可达或连接超时")
                continue        # http 连接失败时继续试 https
            if reason == "challenge":
                last = _result(name, "fail", "-", "被 CDN 人机验证拦截",
                               "收到 Cloudflare 等 CDN 的验证挑战页，已重试 %d 次；"
                               "不是设备问题，稍后重试或改用直连地址"
                               % CHALLENGE_RETRIES)
                break
            return _result(name, "fail", "-", "未找到 LuCI 登录页",
                           "页面不是 LuCI（无 /cgi-bin/luci 路径或登录表单）")

        ok, method, detail, evidence = try_login_and_verify(
            session, base, probe, username, password)
        if ok:
            return _result(name, "success", method, detail, evidence)
        return _result(name, "fail", method, detail, evidence)

    return last


# ---------------------------------------------------------------------------
# Web 服务
# ---------------------------------------------------------------------------

tasks = {}
tasks_lock = threading.Lock()
TASK_TTL = 600          # 完成后保留 10 分钟，供前端轮询取结果


def _gc_tasks():
    now = time.time()
    with tasks_lock:
        dead = [k for k, v in tasks.items()
                if v.get("done") and now - v.get("finished_at", now) > TASK_TTL]
        for k in dead:
            tasks.pop(k, None)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OpenWrtChecker/" + VERSION

    def log_message(self, fmt, *args):
        pass            # 静音访问日志，避免刷屏 systemd journal

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML)

        if path.startswith("/api/status/"):
            return self.api_status(path.rsplit("/", 1)[-1],
                                   parse_qs(parsed.query))

        if path == "/api/ping":
            return self._json({"ok": True, "version": VERSION})

        return self._send(404, "404 Not Found", "text/plain; charset=utf-8")

    def do_POST(self):
        if urlparse(self.path).path == "/api/check":
            return self.api_check()
        if urlparse(self.path).path.startswith("/api/stop/"):
            return self.api_stop(urlparse(self.path).path.rsplit("/", 1)[-1])
        return self._send(404, "404 Not Found", "text/plain; charset=utf-8")

    def api_check(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return self._json({"error": "请求体不是合法 JSON"}, 400)

        targets = [t.strip() for t in (payload.get("targets") or "").split("\n") if t.strip()]
        username = payload.get("username") or ""
        password = payload.get("password") or ""
        try:
            timeout = max(3, min(int(payload.get("timeout", 8)), 60))
            workers = max(1, min(int(payload.get("workers", 20)), 200))
        except (TypeError, ValueError):
            return self._json({"error": "超时/并发数必须是数字"}, 400)

        if not targets or not username:
            return self._json({"error": "请输入目标和用户名"}, 400)

        _gc_tasks()
        task_id = uuid.uuid4().hex[:8]
        with tasks_lock:
            tasks[task_id] = {"results": [], "done": False, "cancel": False,
                              "success": 0, "fail": 0, "total": len(targets),
                              "started_at": time.time(), "finished_at": 0}

        threading.Thread(target=self._run_task,
                         args=(task_id, targets, username, password, timeout, workers),
                         daemon=True).start()
        return self._json({"task_id": task_id})

    def api_stop(self, task_id):
        with tasks_lock:
            if task_id in tasks:
                tasks[task_id]["cancel"] = True
        return self._json({"ok": True})

    def api_status(self, task_id, query):
        with tasks_lock:
            task = tasks.get(task_id)
            if task is None:
                return self._json({"error": "任务不存在或已过期"}, 404)
            try:
                since = max(0, int((query.get("since") or ["0"])[0]))
            except ValueError:
                since = 0
            results = task["results"][since:]
            return self._json({
                "results": results,
                "next": since + len(results),
                "done": task["done"],
                "total": task["total"],
                "success": task["success"],
                "fail": task["fail"],
            })

    @staticmethod
    def _run_task(task_id, targets, username, password, timeout, workers):
        with tasks_lock:
            task = tasks.get(task_id)
        if task is None:
            return

        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = {pool.submit(check_openwrt, t, username, password, timeout): t
                       for t in targets}
            for future in as_completed(futures):
                with tasks_lock:
                    if task["cancel"]:
                        break
                try:
                    result = future.result()
                except Exception as e:
                    result = _result(futures[future], "fail", "-",
                                     "内部错误：%s" % str(e)[:40])
                with tasks_lock:
                    if result["status"] == "success":
                        task["success"] += 1
                    else:
                        task["fail"] += 1
                    task["results"].append(result)
        finally:
            try:
                pool.shutdown(wait=False, cancel_futures=True)   # Python 3.9+
            except TypeError:
                pool.shutdown(wait=False)
            with tasks_lock:
                task["done"] = True
                task["finished_at"] = time.time()


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenWrt / LuCI 登录检测 v5</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #0f1117; color: #e0e0e0; min-height: 100vh; }
.container { max-width: 1100px; margin: 0 auto; padding: 20px; }
h1 { text-align: center; margin-bottom: 6px; font-size: 22px; color: #7eb8ff; }
.sub { text-align: center; font-size: 12px; color: #666; margin-bottom: 22px; }
.card { background: #1a1d27; border-radius: 12px; padding: 20px; margin-bottom: 16px; border: 1px solid #2a2d3a; }
label { display: block; font-size: 13px; color: #888; margin-bottom: 6px; }
textarea, input { width: 100%; background: #12141c; border: 1px solid #2a2d3a; border-radius: 8px; color: #e0e0e0; padding: 10px 12px; font-size: 14px; font-family: "SF Mono", Menlo, Consolas, monospace; }
textarea { height: 150px; resize: vertical; }
input:focus, textarea:focus { outline: none; border-color: #7eb8ff; }
.row { display: flex; gap: 12px; margin-bottom: 12px; }
.row > * { flex: 1; }
.btn { display: block; width: 100%; padding: 12px; background: linear-gradient(135deg, #4a7dff, #7eb8ff); color: #fff; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }
.btn:hover { box-shadow: 0 4px 20px rgba(74,125,255,.3); }
.btn.stop { background: linear-gradient(135deg, #ff4a4a, #ff8e8e); }
.stats { display: flex; gap: 12px; margin-bottom: 12px; }
.stat { flex: 1; background: #12141c; border-radius: 8px; padding: 12px; text-align: center; }
.stat .num { font-size: 28px; font-weight: 700; }
.stat.success .num { color: #4ade80; }
.stat.fail .num { color: #f87171; }
.stat.total .num { color: #7eb8ff; }
.progress-bar { height: 4px; background: #2a2d3a; border-radius: 2px; margin-bottom: 12px; overflow: hidden; }
.progress-bar .fill { height: 100%; background: linear-gradient(90deg, #4a7dff, #7eb8ff); transition: width .3s; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #12141c; padding: 10px; text-align: left; font-weight: 600; color: #888; border-bottom: 1px solid #2a2d3a; position: sticky; top: 0; z-index: 1; }
td { padding: 10px; border-bottom: 1px solid #1e2130; vertical-align: top; }
tr:hover td { background: #1e2130; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.badge.ok { background: #064e3b; color: #4ade80; }
.badge.no { background: #7f1d1d; color: #f87171; }
.ev { color: #7a7f8c; font-size: 12px; }
.mono { font-family: "SF Mono", Menlo, Consolas, monospace; }
.hidden { display: none; }
.hint { font-size: 12px; color: #666; margin-top: 4px; line-height: 1.6; }
.toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.toolbar button { background: #2a2d3a; color: #7eb8ff; border: 1px solid #3a3d4a; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }
.result-table { max-height: 560px; overflow-y: auto; }
.new-row { animation: flashIn .5s; }
@keyframes flashIn { from { background: #1a3a2a; } to { background: transparent; } }
.running-indicator { display: inline-block; width: 8px; height: 8px; background: #4ade80; border-radius: 50%; margin-right: 6px; animation: pulse 1s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .3; } }
</style>
</head>
<body>
<div class="container">
  <h1>OpenWrt / LuCI 批量登录检测</h1>
  <div class="sub">判定原则：必须拿到 sysauth 会话 + 回访后台页确认真登录成功；非 LuCI 页面一律判失败</div>

  <div class="card">
    <label>目标列表（IP:端口 或 http(s)://IP:端口，每行一个）</label>
    <textarea id="targets" placeholder="192.168.100.1&#10;192.168.1.1:80&#10;10.0.0.1:8080&#10;https://192.168.2.1:443"></textarea>
    <div class="hint">只填 IP 或 IP:端口时，会先试 http，连接失败再自动试 https</div>
  </div>

  <div class="card">
    <div class="row">
      <div><label>用户名</label><input type="text" id="username" placeholder="root" value="root"></div>
      <div><label>密码</label><input type="password" id="password" placeholder="密码"></div>
    </div>
    <div class="row">
      <div><label>超时（秒）</label><input type="number" id="timeout" value="8" min="3" max="60"></div>
      <div><label>并发数</label><input type="number" id="workers" value="20" min="1" max="200"></div>
    </div>
  </div>

  <button class="btn" id="startBtn" onclick="startCheck()">开始检测</button>

  <div id="resultArea" class="hidden" style="margin-top: 16px;">
    <div class="card">
      <div class="progress-bar"><div class="fill" id="progressFill" style="width:0%"></div></div>
      <div class="stats">
        <div class="stat total"><div class="num" id="doneCount">0</div><div>已检测</div></div>
        <div class="stat success"><div class="num" id="successCount">0</div><div>成功</div></div>
        <div class="stat fail"><div class="num" id="failCount">0</div><div>失败</div></div>
      </div>
      <div class="toolbar">
        <span id="runStatus" style="font-size:13px;color:#888;"></span>
        <button id="copyBtn" onclick="copySuccess()" class="hidden">复制成功列表</button>
        <button id="copyAllBtn" onclick="copyAll()" class="hidden">复制全部结果</button>
      </div>
    </div>

    <div class="card">
      <div class="result-table">
        <table>
          <thead><tr><th style="width:44px">#</th><th style="width:190px">IP:端口</th><th style="width:100px">状态</th><th style="width:100px">方式</th><th style="width:190px">详情</th><th>判定依据</th></tr></thead>
          <tbody id="resultBody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
let running = false, taskId = null, since = 0, timer = null, rowNum = 0;
let successList = [], allResults = [];

function esc(s) {
  return String(s === undefined || s === null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function setStatus(html) { document.getElementById("runStatus").innerHTML = html; }

async function startCheck() {
  if (running) { stopCheck(true); return; }

  const targets = document.getElementById("targets").value.trim();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const timeout = document.getElementById("timeout").value;
  const workers = document.getElementById("workers").value;

  if (!targets) return alert("请输入目标列表");
  if (!username) return alert("请输入用户名");

  running = true; since = 0; rowNum = 0; successList = []; allResults = [];
  document.getElementById("resultBody").innerHTML = "";
  document.getElementById("doneCount").textContent = "0";
  document.getElementById("successCount").textContent = "0";
  document.getElementById("failCount").textContent = "0";
  document.getElementById("progressFill").style.width = "0%";
  document.getElementById("resultArea").classList.remove("hidden");
  document.getElementById("copyBtn").classList.add("hidden");
  document.getElementById("copyAllBtn").classList.add("hidden");
  setStatus('<span class="running-indicator"></span>检测中...');
  const btn = document.getElementById("startBtn");
  btn.textContent = "停止"; btn.classList.add("stop");

  try {
    const resp = await fetch("/api/check", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({targets, username, password, timeout, workers})
    });
    const data = await resp.json();
    if (data.error) { alert(data.error); stopCheck(); return; }
    taskId = data.task_id;
    poll();
  } catch (e) {
    alert("请求失败: " + e.message); stopCheck();
  }
}

async function poll() {
  if (!running) return;
  try {
    const r = await fetch("/api/status/" + taskId + "?since=" + since);
    const d = await r.json();
    if (d.error) { alert(d.error); stopCheck(); return; }

    for (const item of d.results) { addRow(item); }
    since = d.next;
    allResults = allResults.concat(d.results);

    document.getElementById("successCount").textContent = d.success;
    document.getElementById("failCount").textContent = d.fail;
    document.getElementById("doneCount").textContent = d.success + d.fail;
    document.getElementById("progressFill").style.width =
      Math.round((d.success + d.fail) / Math.max(1, d.total) * 100) + "%";

    if (d.done) { stopCheck(); return; }
    timer = setTimeout(poll, 300);
  } catch (e) {
    timer = setTimeout(poll, 800);
  }
}

function addRow(r) {
  rowNum++;
  const tbody = document.getElementById("resultBody");
  const tr = document.createElement("tr");
  tr.className = "new-row";
  const ok = r.status === "success";
  tr.innerHTML =
    '<td class="mono">' + rowNum + '</td>' +
    '<td class="mono">' + esc(r.ip) + '</td>' +
    '<td><span class="badge ' + (ok ? 'ok' : 'no') + '">' + (ok ? '成功' : '失败') + '</span></td>' +
    '<td class="mono">' + esc(r.method) + '</td>' +
    '<td>' + esc(r.detail) + '</td>' +
    '<td class="ev">' + esc(r.evidence || '') + '</td>';
  if (ok) {
    tr.dataset.ok = "1";
    successList.push(r.ip);
    const firstFail = tbody.querySelector('tr[data-ok="0"]');
    if (firstFail) { tbody.insertBefore(tr, firstFail); } else { tbody.appendChild(tr); }
  } else {
    tr.dataset.ok = "0";
    tbody.appendChild(tr);
  }
}

function stopCheck(sendStop) {
  running = false;
  if (timer) { clearTimeout(timer); timer = null; }
  if (sendStop && taskId) { fetch("/api/stop/" + taskId, {method: "POST"}).catch(function(){}); }
  const btn = document.getElementById("startBtn");
  btn.textContent = "开始检测"; btn.classList.remove("stop");
  setStatus("检测完成");
  if (successList.length > 0) document.getElementById("copyBtn").classList.remove("hidden");
  if (allResults.length > 0) document.getElementById("copyAllBtn").classList.remove("hidden");
}

function copySuccess() { copyText(successList.join("\n"), "copyBtn", "复制成功列表"); }

function copyAll() {
  const txt = allResults.map(function(r) {
    return [(r.status === "success" ? "成功" : "失败"), r.ip, r.method, r.detail].join("\t");
  }).join("\n");
  copyText(txt, "copyAllBtn", "复制全部结果");
}

function copyText(text, btnId, label) {
  navigator.clipboard.writeText(text).then(function() {
    const btn = document.getElementById(btnId);
    btn.textContent = "已复制";
    setTimeout(function() { btn.textContent = label; }, 1500);
  });
}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# 本地自测（不需要路由器）：证明「非 LuCI 页面不会被判成功」
# ---------------------------------------------------------------------------

_SELFTEST_LOGIN = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>LuCI - OpenWrt Configuration Interface</title>
<link rel="stylesheet" href="/luci-static/resources/bootstrap/css/bootstrap.min.css">
</head><body><form method="post" action="/cgi-bin/luci/">
<input type="text" name="luci_username" /><input type="password" name="luci_password" />
<input type="submit" value="Login" /></form></body></html>"""

_SELFTEST_LOGIN_CUSTOM = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>iStoreOS</title><link rel="stylesheet" href="/luci-static/resources/istore/theme.css">
</head><body><form method="post" action="/cgi-bin/luci/">
<input type="text" name="username" /><input type="password" name="password" />
<input type="submit" value="登录" /></form></body></html>"""

_SELFTEST_ADMIN = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Status - LuCI</title>
<link rel="stylesheet" href="/luci-static/resources/bootstrap/css/bootstrap.min.css">
</head><body>
<div id="mainmenu"><a href="/cgi-bin/luci/admin/status/overview">Overview</a>
<a href="/cgi-bin/luci/admin/system/system">System</a></div>
<h2>Overview</h2>
<div class="cbi-section"><h3>登录失败尝试</h3>
<p>authentication failed: 3 次；密码错误 2 次；认证失败 1 次</p></div>
<p>system admin 网络 状态 管理</p></body></html>"""

_SELFTEST_FAKE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>设备管理</title></head>
<body><h1>设备管理后台</h1><p>Powered by OpenWrt 兼容固件</p>
<p>system admin 网络 状态 管理 overview logout 退出</p></body></html>"""

_SELFTEST_OTHER_LOGIN = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Some NAS Login</title></head>
<body><form method="post" action="/login"><input type="text" name="user" />
<input type="password" name="pass" /><input type="submit" value="Sign in" /></form>
<p>system admin 网络</p></body></html>"""

# 模拟 Cloudflare 人机验证挑战页
_SELFTEST_CHALLENGE = """<!doctype html><html class="no-js ie6 oldie" lang="en-US"><head>
<title>Just a moment...</title><meta http-equiv="refresh" content="0">
<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>
</head><body><div id="cf-challenge-running">Checking your browser before accessing.</div>
<script>window.__cf_chl_opt={cvId:'3'};</script></body></html>"""

_SELFTEST_PW = "good-password"


def _selftest_handler(mode):
    from http.server import BaseHTTPRequestHandler

    # cf_retry：前 2 次请求下发挑战页，之后放行（模拟真实 CDN 间歇拦截）
    # cf_block：始终下发挑战页
    state = {"hits": 0}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _out(self, code, body, extra=None):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _redir(self, loc, cookie=None):
            self.send_response(302)
            self.send_header("Location", loc)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _authed(self):
            return "sysauth=" in (self.headers.get("Cookie") or "")

        def _basic_ok(self):
            exp = "Basic " + base64.b64encode(("root:" + _SELFTEST_PW).encode()).decode()
            return (self.headers.get("Authorization") or "") == exp

        def _maybe_challenge(self):
            """返回 True 表示本次已下发挑战页。"""
            if mode == "cf_block":
                self._out(403, _SELFTEST_CHALLENGE)
                return True
            if mode == "cf_retry":
                state["hits"] += 1
                if state["hits"] <= 2:
                    self._out(403, _SELFTEST_CHALLENGE)
                    return True
            return False

        def _eff_mode(self):
            if mode == "cf_retry":
                return "luci"
            return mode

        def do_GET(self):
            path = re.sub(r"/{2,}", "/", re.sub(r";[^/]*", "", urlparse(self.path).path))
            if self._maybe_challenge():
                return
            m = self._eff_mode()

            if m == "fake":
                return self._out(200, _SELFTEST_FAKE)
            if m == "other_login":
                return self._out(200, _SELFTEST_OTHER_LOGIN)

            if m == "luci_basic":
                if not self._basic_ok():
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="LuCI"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path.rstrip("/") in ("/cgi-bin/luci", ""):
                    return self._redir("/cgi-bin/luci/admin/status/overview",
                                       "sysauth_http=beef01; Path=/; HttpOnly")
                if path.startswith("/cgi-bin/luci/admin"):
                    return self._out(200, _SELFTEST_ADMIN,
                                     {"Set-Cookie": "sysauth_http=beef01; Path=/; HttpOnly"})
                return self._out(404, "<h1>Not Found</h1>")

            login_html = _SELFTEST_LOGIN_CUSTOM if m == "luci_custom" else _SELFTEST_LOGIN

            if path.rstrip("/") in ("/cgi-bin/luci", ""):
                if self._authed():
                    return self._redir("/cgi-bin/luci/admin/status/overview")
                return self._out(200, login_html)

            if path.startswith("/cgi-bin/luci/admin"):
                if not self._authed():
                    return self._redir("/cgi-bin/luci/")
                if m == "luci_stok" and ";stok=" not in self.path:
                    return self._redir("/cgi-bin/luci/;stok=a1b2c3/admin/status/overview")
                return self._out(200, _SELFTEST_ADMIN)

            if path.startswith("/luci-static/"):
                return self._out(200, "/* css */")

            return self._out(404, "<h1>Not Found</h1>")

        def do_POST(self):
            if self._maybe_challenge():
                return
            m = self._eff_mode()

            if m == "fake":
                return self._out(200, _SELFTEST_FAKE)
            if m == "other_login":
                return self._out(200, _SELFTEST_OTHER_LOGIN)
            if m == "luci_basic":
                return self._out(404, "<h1>Not Found</h1>")

            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "ignore")
            q = parse_qs(body)
            pwd = (q.get("luci_password") or q.get("password") or [""])[0]
            if pwd == _SELFTEST_PW:
                return self._redir("/cgi-bin/luci/", "sysauth=deadbeefcafe; Path=/; HttpOnly")
            login_html = _SELFTEST_LOGIN_CUSTOM if m == "luci_custom" else _SELFTEST_LOGIN
            # 模拟实测固件：认证失败时返回 403 + 登录页且无错误文案
            code = 403 if m in ("luci", "luci_stok") else 200
            return self._out(code, login_html)

    return H


def run_selftest():
    global CHALLENGE_RETRIES, CHALLENGE_DELAY
    saved = (CHALLENGE_RETRIES, CHALLENGE_DELAY)
    CHALLENGE_RETRIES, CHALLENGE_DELAY = 3, 0.1     # 自测时缩短退避等待

    cases = [
        ("fake", "非 LuCI 页面（含 openwrt/system/网络 泛词）", "fail"),
        ("other_login", "非 LuCI 的普通登录页（不在 /cgi-bin/luci）", "fail"),
        ("luci", "标准 LuCI 登录页 + 正确密码", "success"),
        ("luci_stok", "LuCI 后台页要求 ;stok= 的版本 + 正确密码", "success"),
        ("luci_custom", "自定义主题改名字段 + 正确密码", "success"),
        ("luci", "标准 LuCI + 错误密码", "fail"),
        ("luci_custom", "自定义主题 + 错误密码", "fail"),
        ("luci_basic", "uhttpd Basic Auth 模式 + 正确密码", "success"),
        ("luci_basic", "uhttpd Basic Auth 模式 + 错误密码", "fail"),
        ("cf_retry", "CDN 挑战页后放行（退避重试应恢复正常）", "success"),
        ("cf_block", "CDN 持续拦截（应判失败并说明原因）", "fail"),
    ]

    # 每个用例起一个独立端口的模拟路由器（端口 0 = 由系统分配空闲端口）
    started = []
    for mode, desc, expect in cases:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _selftest_handler(mode))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append({"mode": mode, "desc": desc, "expect": expect,
                        "port": srv.server_address[1], "srv": srv})

    print("=" * 96)
    print("本地自测：%d 个模拟目标（不需要路由器）" % len(started))
    print("=" * 96)
    print("%-14s%-44s%-9s%-9s%s" % ("目标类型", "场景", "期望", "实际", "结论"))
    print("-" * 96)

    bad = 0
    try:
        for c in started:
            pwd = "bad-password" if "错误" in c["desc"] else _SELFTEST_PW
            r = check_openwrt("127.0.0.1:%d" % c["port"], "root", pwd, timeout=5)
            ok = r["status"] == c["expect"]
            if not ok:
                bad += 1
            print("%-14s%-44s%-9s%-9s%s" % (
                c["mode"], c["desc"], c["expect"], r["status"],
                "通过" if ok else "不通过 <-- " + r["detail"]))
            print("%-14s依据: %s" % ("", r.get("evidence") or r.get("detail")))
    finally:
        for c in started:
            c["srv"].shutdown()
            c["srv"].server_close()
        CHALLENGE_RETRIES, CHALLENGE_DELAY = saved

    print("-" * 96)
    print("不符预期用例数：%d / %d" % (bad, len(started)))
    print("=" * 96)
    return 0 if bad == 0 else 1


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def is_port_free(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def local_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    return ips


def serve(host, port):
    if not is_port_free(host, port):
        print("[错误] 端口 %d 已被占用。" % port, file=sys.stderr)
        print("       可用 netstat -tlnp | grep %d 查看占用进程，" % port, file=sys.stderr)
        print("       或用 --port 换一个端口。", file=sys.stderr)
        return 1

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True

    print("=" * 62)
    print("  OpenWrt / LuCI 批量登录检测  (%s)" % VERSION)
    print("=" * 62)
    print("  已监听    %s:%d" % (host, port))
    print("  本机访问  http://127.0.0.1:%d/" % port)
    for ip in local_ips():
        print("  局域网访问 http://%s:%d/" % (ip, port))
    if host == "0.0.0.0":
        print("  提示      监听 0.0.0.0，同一网络的机器均可访问本页面")
    print("  停止服务  Ctrl+C")
    print("=" * 62)
    print(flush=True)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止服务...", flush=True)
    finally:
        httpd.shutdown()
        httpd.server_close()
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="OpenWrt / LuCI 批量登录检测（Linux 零依赖单文件版）")
    ap.add_argument("--host", default=os.environ.get("OPENWRT_CHECKER_HOST", DEFAULT_HOST),
                    help="监听地址，默认 0.0.0.0")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("OPENWRT_CHECKER_PORT", DEFAULT_PORT)),
                    help="监听端口，默认 5678")
    ap.add_argument("--selftest", action="store_true",
                    help="运行本地自测（不需要路由器），验证不会误判")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()

    if sys.version_info < (3, 6):
        print("[错误] 需要 Python 3.6 或更高版本，当前为 %s" % sys.version.split()[0],
              file=sys.stderr)
        return 1
    return serve(args.host, args.port)


if __name__ == "__main__":
    sys.exit(main())
