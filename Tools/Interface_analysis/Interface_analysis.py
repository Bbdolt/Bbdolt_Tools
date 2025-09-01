import requests
import json
import os
import argparse
from tqdm import tqdm
import datetime
from urllib.parse import urlparse
import random
import re


# 颜色定义
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"

static_type = [".js", ".html"]

# 获取 json 文件
with open("./ai_config.json", "r", encoding="utf-8") as f:
    json_data = json.load(f)
output = ""

# 配置API密钥
API_TOKEN = json_data.get('API_TOKEN', "")
API_URL = json_data.get('openai_url', 'https://api.siliconflow.cn/v1') + "/chat/completions"
MODEL_NAME = json_data.get('MODEL_NAME', 'Qwen/Qwen2.5-Coder-7B-Instruct')

def remove_params_from_uri(uri):
    """去除URI中的参数部分"""
    parsed = urlparse(uri)
    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path
    return f"{scheme}://{netloc}{path}"

def analyze_uris(uri_list, progress_bar):
    # 系统prompt配置
    system_prompt = json_data.get('system_prompt', "")
    
    # 构建对话消息
    messages = [
        {
            "role": "system",
            "content": f"你是一个专业的URI安全分析引擎。严格遵循以下分析规范：{json.dumps(system_prompt, ensure_ascii=False)}"
        },
        {
            "role": "user",
            "content": f"请分析以下URI列表：{json.dumps(uri_list, ensure_ascii=False)}"
        }
    ]

    # API请求参数
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 4000
    }

    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            API_URL, 
            json=payload, 
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.RequestException as e:
        print(f"{RED}API请求错误: {str(e)}{RESET}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"{RED}响应内容: {e.response.text[:500]}{RESET}")
        return None
    except json.JSONDecodeError:
        print(f"{RED}API响应解析失败{RESET}")
        return None
    finally:
        progress_bar.update(len(uri_list))  # 更新进度条

def analyze_uris_in_batches(uri_list, batch_size=15):
    all_results = []
    total_uris = len(uri_list)
    with tqdm(total=total_uris, desc="总进度", unit="URI") as progress_bar:
        for i in range(0, total_uris, batch_size):
            # 获取当前批次的URI列表
            batch_uris = uri_list[i:i + batch_size]
            
            # 对当前批次进行分析
            batch_result = analyze_uris(batch_uris, progress_bar)
            
            if batch_result is not None:
                all_results.append(batch_result)
            else:
                print(f"{RED}警告: 批次{i}分析失败{RESET}")

    return all_results

def parse_custom_format(content):
    """解析自定义格式的URI数据文件，并处理重复的URI保留response_size最大的那一项"""
    uri_list = []
    lines = content.split('\n')
    uri_map = {}  # 用于存储去除参数后的URI和对应的response_size
    url_list2 = []
    url_map = {}  # 用于存储去除参数后的URL和对应的完整URL
    uri_list2 = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # 分割字符串来获取 uri, response_size 和 full_uri
        parts = line.split(',')
        if len(parts) < 3:
            uri_list.append({
                "uri": line,
                "response_size": -1,
            })
            continue

        uri = parts[0]
        try:
            response_size = int(parts[1])
        except ValueError:
            response_size = -1

        full_uri = parts[2] if len(parts) >= 3 else None

        # 去除URI中的参数部分
        uri_without_params = remove_params_from_uri(uri)

        # 如果是新URI或者当前response_size更大，则更新
        if uri_without_params not in uri_map or response_size > uri_map[uri_without_params]['response_size']:
            uri_map[uri_without_params] = {
                "uri": uri,
                "response_size": response_size,
            }

        if full_uri:
            # 去除URL中的参数部分
            url_without_params = remove_params_from_uri(full_uri)
            # 检查URL是否为.js或.html类型
            url_path = urlparse(full_uri).path
            path_without_extension = "/".join(url_path.split('/')[:-1])
            extension = url_path.split('.')[-1] if '.' in url_path else ''
            
            if extension in ['js', 'html']:
                url_key = f"{path_without_extension}.{extension}"
            else:
                url_key = url_without_params

            if url_key not in url_map:
                url_map[url_key] = full_uri
                url_list2.append(full_uri)

    # 将处理后的结果添加到uri_list中
    for _, item in uri_map.items():
        # uri_list2.append(item['uri'])
        uri_list.append(item)

    return uri_list, url_list2

def read_uris_from_file(file_path):
    if not os.path.exists(file_path):
        print(f"{RED}文件不存在: {file_path}{RESET}")
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                # 先尝试作为JSON文件读取
                uri_list = json.load(f)
                print(f"{GREEN}从文件加载了 {len(uri_list)} 个URI (JSON格式){RESET}")
                return uri_list,None,None
            except json.JSONDecodeError:
                # 如果不是JSON格式，则按自定义格式解析
                f.seek(0)  # 回到文件开头
                content = f.read()
                uri_list,url_list2 = parse_custom_format(content)
                print(f"{GREEN}从文件加载了 {len(uri_list)} 个URI (自定义格式){RESET}")
                return uri_list,url_list2
    except Exception as e:
        print(f"{RED}文件读取失败: {str(e)}{RESET}")
        return None

def read_uris_from_json_string(json_string):
    try:
        uri_list = json.loads(json_string)
        print(f"{GREEN}直接解析了 {len(uri_list)} 个URI{RESET}")
        return uri_list
    except json.JSONDecodeError:
        print(f"{RED}输入不是有效的JSON格式{RESET}")
        return None

def process_and_sort_results(all_results):
    all_uris = []

    for result_batch in all_results:
        if result_batch is not None:
            try:
                # 提取并解析结果
                if 'choices' in result_batch and result_batch['choices']:
                    content = result_batch['choices'][0]['message']['content']
                    json_data = re.search(r'```json(.*?)```', content, re.DOTALL)
                    if json_data:
                        analysis_result = json_data.group(1).strip()
                    else:
                        analysis_result = result_batch['choices'][0]['message']['content'].replace("```json",'').replace('```','')
                    analysis_result = json.loads(analysis_result)
                    answers = analysis_result['uris']

                    all_uris.extend(answers)
                else:
                    print(f"{RED}API返回结果格式异常{RESET}")
                    print(json.dumps(result_batch, indent=2))
            except KeyError as e:
                print(f"{RED}结果解析出错: {str(e)}{RESET}")
                print(f"{RED}完整响应:{RESET}")
                print(json.dumps(result_batch, indent=2))
        else:
            print(f"{RED}批次分析失败{RESET}")

    return all_uris

def print_results(all_uris):
    # 首先，按 risk_score 的值降序排序 all_uris 列表
    uri_list22 = []
    sorted_uris = sorted(all_uris, key=lambda x: x['risk_score'], reverse=True)
    global output
    
    print(f"{BOLD}=" * 50 +RESET)
    output += f"AI分析结果：\n"
    print(f"{BOLD}AI分析结果：{RESET}\n")
    for result in sorted_uris:
        risk_score = result['risk_score']
        visual_label = result['visual_label']
        uri = result['uri']
        response_size = result['response_size']
        vulnerability = result['vulnerability']
        explanation = result['explanation']
        
        if risk_score >= 7:
            color = RED
        elif risk_score >= 4:
            color = YELLOW
        else:
            color = GREEN
        
        output += f"{risk_score}（{visual_label}） {uri} [{response_size}] 可能存在{vulnerability} -> {explanation}\n"
        print(f"{color}{risk_score}（{visual_label}） {uri} [{response_size}] 可能存在{vulnerability} -> {explanation}{RESET}")

    output += f"\n排序后的URI列表：\n"
    print(f"{BOLD}排序后的URI列表：{RESET}\n")
    for result in sorted_uris:
        output += f"{result['uri']}\n"
        print(f"{result['uri']}")
        uri_list22.append(result['uri'])
    return uri_list22
    
def print_analyze_urls(input_data, progress_bar=None):
    url_result = []
    # 系统prompt配置
    pinjie_prompt = """{"task":"URI路径拼接风险分析，并输出指定JSON格式","problem":"直接拼接域名和JS提取的URI导致404错误","requirements":["分析成功路径与原始URI的拼接规律","推测可能的base_url或路径转换规则","生成无404风险的完整URL"],"input_data":{"successful_path":["https://api.service.com/base/v1/users/info","https://api.service.com/base/v2/orders","https://auth.service.com/identity/token","https://cdn.service.com/assets/fonts/"],"raw_uris":["/base/v3/products",//绝对路径（新版本）"./details",//当前目录相对路径"../config",//父目录相对路径"api/endpoint"//无前缀相对路径]},"output_format":{"强制要求":"结果必须是纯JSON，无额外文本","强制JSON结构":{"results":[{"possible_results":["完整URL1","完整URL2"]}],"global_patterns":"拼接规则描述"},"results":[{"possible_results":["https://api.service.com/base/v3/products"]},{"possible_results":["https://api.service.com/base/v2/details"]},{"possible_results":["https://api.service.com/base/config","https://cdn.service.com/config"//多域名方案]},{"possible_results":["https://api.service.com/base/v2/api/endpoint"]}],"global_patterns":["BaseURL规则: api.service.com使用/base/{version}/, auth.service.com使用/identity/, cdn.service.com使用/assets/","相对路径解析: ./ 继承最近同域成功路径目录，../ 回溯父目录（可能跨域）","版本推断: 未出现版本号时继承最近版本（如v2），新版本（v3）延续现有模式"]},"special_cases":{"multi_scenario_rules":{"relative_paths":{"./":"基于最近同域名成功路径（如最后api请求是/base/v2/orders -> ./details = /base/v2/details）","../":"优先回溯同域名路径，无匹配时启用跨域方案（如../config 可能指向 /base/ 或 /assets/）"},"version_handling":"新版本号（v3）延续现有API域名规则，静态资源路径默认使用CDN域名","domain_fallback":"歧义路径提供2个最可能的域名方案（基于路径关键字：api->service, config->cdn）"},"confidence_indicators":["路径重复度：/base/ 在成功路径出现3次（高置信）","域名占比：api.service.com占75%请求（主域名）","层级深度：成功路径平均3级目录，相对路径需匹配此深度"]}"""
    content = json.dumps(input_data, ensure_ascii=False)
    # print(content)
    # 构建对话消息
    messages = [
        {
            "role": "system",
            "content": f"你是一个专业的URI安全分析引擎。严格遵循以下分析规范：{pinjie_prompt}"
        },
        {
            "role": "user",
            "content": f'{content}'
        }
    ]

    # API请求参数
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 4000
    }

    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            API_URL, 
            json=payload, 
            headers=headers
        )
        response.raise_for_status()
        result = response.json()
        content = result['choices'][0]['message']['content']
        json_data = re.search(r'```json(.*?)```', content, re.DOTALL)
        if json_data:
            json_data_url = json_data.group(1).strip()
        else:
            json_data_url = content.replace("```json",'').replace('```','')
        results = json.loads(json_data_url)['results']
        for data2 in results:
            for iii in data2['possible_results']:
                url_result.append(iii)
        if progress_bar is not None:
            # 更新进度条，每次处理完一个 chunk 更新进度条
            progress_bar.update(len(input_data['raw_uris']))
    except:
        print("error")
    
    return url_result

def pinjie_url(uri_list2, url_list2):
    input_data = {"successful_path": None, "raw_uris": None}
    print_result = []
    if len(url_list2) > 20:
        input_data['successful_path'] = random.sample(url_list2, 20)
    else:
        input_data['successful_path'] = url_list2
    
    print(f"\n{BOLD}URL拼接后结果{RESET}")
    global output
    output += "\nURL拼接后结果:\n"
    total_urls = len(uri_list2)
    with tqdm(total=total_urls, desc="总进度", unit="URL") as progress_bar:
        for i in range(0, len(uri_list2), 15):
            chunk = uri_list2[i:i + 15]
            input_data['raw_uris'] = chunk
            chunk_result = print_analyze_urls(input_data, progress_bar)
            print_result.extend(chunk_result)
    print(f"{BOLD}=" * 50 +RESET)
    print('\n'.join(print_result))
    output += '\n'.join(print_result)

def main():
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description='URI安全分析工具')
    parser.add_argument('-r', '--read', help='输入URI数据的文件路径')
    parser.add_argument('-s', '--string', help='输入URI数据的JSON字符串')
    parser.add_argument('-o', '--output', help='输出结果的文件路径，输入值为 - 时，自动创建文件')
    parser.add_argument('-n', '--next', action='store_true', help='是否进一步拼接url')

    args = parser.parse_args()
    next = args.next

    uri_list = None

    # 根据参数选择读取方式
    if args.read:
        uri_list,url_list2 = read_uris_from_file(args.read)
    elif args.string:
        uri_list = read_uris_from_json_string(args.string)
        next = False
    
    if uri_list is None:
        return
    
    if url_list2 == None or url_list2==[]:
        next = False

    # 验证输入数据结构
    if not isinstance(uri_list, list):
        print(f"{RED}输入格式错误：应提供URI数组{RESET}")
        return
    
    # 执行分析
    results = analyze_uris_in_batches(uri_list)
    all_uris = process_and_sort_results(results)
    if args.output == '-':
        output_file = None
    else:
        output_file = args.output
    uri_list2 = print_results(all_uris)
    if next:
        pinjie_url(uri_list2,url_list2)
    
    if output_file:
        output_file = os.path.join("data", output_file)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"结果已保存至 {output_file}")
    else:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H%M-%S")
        default_file_name = f"data/{current_time}.txt"
        with open(default_file_name, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"结果已保存至 {default_file_name}")

if __name__ == "__main__":
    main()
