import requests
import sys
requests.packages.urllib3.disable_warnings()

target = sys.argv[1] if len(sys.argv) > 1 else "192.168.100.1:80"
session = requests.Session()
session.verify = False

for path in ["/", "/cgi-bin/luci", "/login", "/login.html"]:
    url = f"http://{target}{path}"
    try:
        r = session.get(url, timeout=8, allow_redirects=True)
        print(f"=== {path} ===")
        print(f"状态码: {r.status_code}")
        print(f"最终URL: {r.url}")
        print(f"Content-Type: {r.headers.get('content-type', '?')}")
        print(f"内容前800字:")
        print(r.text[:800])
        print()
    except Exception as e:
        print(f"{path} 失败: {e}")
        print()
