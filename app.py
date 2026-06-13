#!/usr/bin/env python3
"""
OpenWrt 路由器批量登录检测工具 - Web 版 v4 (POST + 流式)
"""

from flask import Flask, render_template, request, Response
from flask_cors import CORS
import requests
import re
import json
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
CORS(app)
requests.packages.urllib3.disable_warnings()

# 任务存储
tasks = {}


def check_openwrt(ip_port, username, password, timeout=8):
    """检测单个 OpenWrt 路由器登录"""
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    paths = ["/cgi-bin/luci/", "/cgi-bin/luci", "/"]

    for path in paths:
        url = f"http://{ip_port}{path}"
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            if resp.status_code not in (200, 403):
                continue
            body = resp.text.lower()
            is_luci = "luci" in body or "openwrt" in body or "immortalwrt" in body
            if not is_luci:
                continue

            # 方法1: 表单登录
            login_data = {"luci_username": username, "luci_password": password}
            login_resp = session.post(url, data=login_data, timeout=timeout, allow_redirects=True)
            result_body = login_resp.text.lower()
            cookies = dict(session.cookies)
            if any(k in cookies for k in ["sysauth_http", "sysauth", "auth"]):
                return {"ip": ip_port, "status": "success", "method": "LuCI表单", "detail": "登录成功"}
            if "luci_username" not in result_body and "luci_password" not in result_body:
                if any(k in result_body for k in ["overview", "状态", "logout", "退出", "system", "网络", "admin", "管理", "luci-static"]):
                    return {"ip": ip_port, "status": "success", "method": "LuCI表单", "detail": "登录成功"}
            fail_signals = ["密码错误", "密码不正确", "用户名或密码", "login failed", "authentication failed", "认证失败", "incorrect password"]
            if any(k in result_body for k in fail_signals):
                return {"ip": ip_port, "status": "fail", "method": "-", "detail": "密码错误"}

            # 方法2: Basic Auth
            try:
                bs = requests.Session()
                bs.verify = False
                br = bs.get(f"http://{ip_port}/cgi-bin/luci/", auth=(username, password), timeout=timeout, allow_redirects=True)
                bc = dict(bs.cookies)
                if any(k in bc for k in ["sysauth_http", "sysauth", "auth"]):
                    return {"ip": ip_port, "status": "success", "method": "BasicAuth", "detail": "登录成功"}
                bb = br.text.lower()
                if "luci_username" not in bb:
                    if any(k in bb for k in ["overview", "状态", "logout", "退出", "system", "网络"]):
                        return {"ip": ip_port, "status": "success", "method": "BasicAuth", "detail": "登录成功"}
            except:
                pass

            return {"ip": ip_port, "status": "fail", "method": "-", "detail": "认证失败"}

        except requests.exceptions.ConnectTimeout:
            return {"ip": ip_port, "status": "fail", "method": "-", "detail": "连接超时"}
        except requests.exceptions.ConnectionError:
            return {"ip": ip_port, "status": "fail", "method": "-", "detail": "连接失败"}
        except Exception as e:
            return {"ip": ip_port, "status": "fail", "method": "-", "detail": str(e)[:50]}

    return {"ip": ip_port, "status": "fail", "method": "-", "detail": "未找到LuCI登录页"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    """创建任务，返回 task_id"""
    data = request.json
    targets = [t.strip() for t in data.get("targets", "").strip().split("\n") if t.strip()]
    username = data.get("username", "")
    password = data.get("password", "")
    timeout = int(data.get("timeout", 8))
    workers = int(data.get("workers", 20))

    if not targets or not username:
        return {"error": "请输入目标和用户名"}, 400

    task_id = str(uuid.uuid4())[:8]
    tasks[task_id] = {"queue": [], "done": False, "success": 0, "fail": 0, "total": len(targets)}

    def run_task():
        total = len(targets)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check_openwrt, t, username, password, timeout): t for t in targets}
            for future in as_completed(futures):
                result = future.result()
                if result["status"] == "success":
                    tasks[task_id]["success"] += 1
                else:
                    tasks[task_id]["fail"] += 1
                done = tasks[task_id]["success"] + tasks[task_id]["fail"]
                result["progress"] = done
                result["total"] = total
                result["success_count"] = tasks[task_id]["success"]
                result["fail_count"] = tasks[task_id]["fail"]
                tasks[task_id]["queue"].append(result)
        tasks[task_id]["done"] = True

    threading.Thread(target=run_task, daemon=True).start()
    return {"task_id": task_id}


@app.route("/api/stream/<task_id>")
def api_stream(task_id):
    """SSE 流式返回结果"""
    if task_id not in tasks:
        return Response("data: " + json.dumps({"error": "任务不存在"}) + "\n\n", mimetype="text/event-stream")

    def generate():
        task = tasks[task_id]
        while True:
            while task["queue"]:
                result = task["queue"].pop(0)
                yield f"data: {json.dumps(result, ensure_ascii=False)}\n\n"
            if task["done"]:
                yield f"data: {json.dumps({'type': 'done', 'total': task['total'], 'success': task['success'], 'fail': task['fail']})}\n\n"
                del tasks[task_id]
                break

    return Response(generate(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5678, debug=False, threaded=True)
