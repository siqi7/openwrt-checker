import requests
import sys
import re
requests.packages.urllib3.disable_warnings()

target = sys.argv[1] if len(sys.argv) > 1 else "192.168.100.1:80"
user = sys.argv[2] if len(sys.argv) > 2 else "root"
pwd = sys.argv[3] if len(sys.argv) > 3 else "mazhenqi777"

session = requests.Session()
session.verify = False

# 试带斜杠的路径
for path in ["/cgi-bin/luci/", "/cgi-bin/luci/admin/", "/cgi-bin/luci/admin/status"]:
    url = f"http://{target}{path}"
    try:
        r = session.get(url, timeout=8, allow_redirects=True)
        print(f"=== {path} ===")
        print(f"状态码: {r.status_code}")
        print(f"最终URL: {r.url}")
        body = r.text
        print(f"长度: {len(body)}")
        # 找表单
        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
        print(f"表单数量: {len(forms)}")
        if forms:
            for i, form in enumerate(forms):
                print(f"  表单{i}: {form[:300]}")
        # 找 input
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', body, re.I)
        print(f"Input字段: {inputs}")
        # 找关键词
        for kw in ["login", "password", "username", "luci_username", "luci_password", "token", "csrf"]:
            if kw.lower() in body.lower():
                print(f"  包含关键词: {kw}")
        print()
    except Exception as e:
        print(f"{path} 失败: {e}\n")

# 试直接 POST 到 /cgi-bin/luci/
print("=== 尝试登录 ===")
login_url = f"http://{target}/cgi-bin/luci/"
login_data = {"luci_username": user, "luci_password": pwd}
try:
    r = session.post(login_url, data=login_data, timeout=8, allow_redirects=True)
    print(f"POST {login_url}")
    print(f"状态码: {r.status_code}")
    print(f"最终URL: {r.url}")
    body = r.text.lower()
    has_fail = any(k in body for k in ["密码错误", "username", "password", "login", "invalid", "incorrect", "请输入"])
    has_admin = any(k in body for k in ["overview", "状态", "概况", "logout", "退出", "system", "网络", "wireless", "无线", "admin", "管理"])
    print(f"有失败关键词: {has_fail}")
    print(f"有管理关键词: {has_admin}")
    print(f"内容前500字: {r.text[:500]}")
    print(f"Cookie: {dict(session.cookies)}")
except Exception as e:
    print(f"登录失败: {e}")

# 试 Basic Auth
print("\n=== 尝试 Basic Auth ===")
try:
    r = session.get(f"http://{target}/cgi-bin/luci/", auth=(user, pwd), timeout=8, allow_redirects=True)
    print(f"状态码: {r.status_code}")
    body = r.text.lower()
    has_admin = any(k in body for k in ["overview", "状态", "概况", "logout", "退出", "system", "网络"])
    print(f"有管理关键词: {has_admin}")
    if has_admin:
        print("✅ Basic Auth 登录成功!")
    print(f"内容前300字: {r.text[:300]}")
except Exception as e:
    print(f"Basic Auth 失败: {e}")
