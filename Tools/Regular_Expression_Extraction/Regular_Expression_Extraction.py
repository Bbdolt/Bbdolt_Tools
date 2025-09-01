import re
import os
import platform
from colorama import init, Fore, Back, Style

# 初始化colorama
init(autoreset=True)

# 正则表达式帮助信息
regex_help = f"""
正则用法:
.        匹配任意单个字符(换行符除外)
\\w      匹配字母、数字或下划线 [a-zA-Z0-9_]
\\d      匹配数字 [0-9]
\\s      匹配空白字符(空格、制表符等)
[abc]    匹配a、b或c中的任意一个字符
[^abc]   匹配不在a、b或c中的任意字符
[0-9]    匹配0到9之间的数字
*        匹配前一个元素0次或多次
+        匹配前一个元素1次或多次
?        匹配前一个元素0次或1次
{{n}}    匹配前一个元素恰好n次
{{n,}}   匹配前一个元素至少n次
{{n,m}}  匹配前一个元素至少n次，最多m次
^        匹配字符串开头(多行模式下匹配行开头)
$        匹配字符串结尾(多行模式下匹配行结尾)
\\b      匹配单词边界
\\B      匹配非单词边界
|        或操作，匹配左侧或右侧表达式
\\       转义特殊字符(如: \\. 匹配点号)
"""

def clear_screen(data_file,result_file):
    """清屏函数，兼容不同操作系统"""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')
        # 显示标题
    print(Fore.MAGENTA + "====== 正则表达式测试工具 ======" + Style.RESET_ALL)
    print(regex_help)
    print(Fore.CYAN + f"数据文件: {data_file}" + Style.RESET_ALL)
    print(Fore.CYAN + f"结果文件: {result_file}" + Style.RESET_ALL)
    print(Fore.YELLOW + "\n输入正则表达式进行匹配，或输入以下命令:" + Style.RESET_ALL)
    print(Fore.GREEN + "  exit - 退出程序" + Style.RESET_ALL)
    print(Fore.GREEN + "  cls  - 清空屏幕" + Style.RESET_ALL)
    

def validate_and_match_regex():
    # 获取当前文件所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_file = os.path.join(current_dir, 'data.txt')
    result_file = os.path.join(current_dir, 'result.txt')
    
    # 显示标题
    print(Fore.MAGENTA + "====== 正则表达式测试工具 ======" + Style.RESET_ALL)
    print(regex_help)
    print(Fore.CYAN + f"数据文件: {data_file}" + Style.RESET_ALL)
    print(Fore.CYAN + f"结果文件: {result_file}" + Style.RESET_ALL)
    print(Fore.YELLOW + "\n输入正则表达式进行匹配，或输入以下命令:" + Style.RESET_ALL)
    print(Fore.GREEN + "  exit - 退出程序" + Style.RESET_ALL)
    print(Fore.GREEN + "  cls  - 清空屏幕" + Style.RESET_ALL)

    while True:
        user_input = input(Fore.GREEN + "\n>>> 请输入: " + Style.RESET_ALL).strip()
        
        if not user_input:
            print(Fore.RED + "输入不能为空，请重新输入。" + Style.RESET_ALL)
            continue
            
        if user_input.lower() == 'exit':
            print(Fore.MAGENTA + "退出程序..." + Style.RESET_ALL)
            return
            
        if user_input.lower() == 'cls':
            clear_screen(data_file,result_file)
            continue
            
        # 处理正则表达式输入
        try:
            # 每次输入时重新读取data.txt文件
            try:
                with open(data_file, 'r', encoding='utf-8') as f:
                    data = f.read()
            except FileNotFoundError:
                print(Fore.RED + f"错误：在当前目录下未找到data.txt文件" + Style.RESET_ALL)
                continue
            except Exception as e:
                print(Fore.RED + f"读取data.txt文件时出错: {e}" + Style.RESET_ALL)
                continue
            
            # 尝试编译正则表达式以验证其有效性
            compiled_re = re.compile(user_input)
            print(Fore.GREEN + "✓ 正则表达式有效" + Style.RESET_ALL)
            
            # 查找所有匹配项
            matches = compiled_re.findall(data)
            
            if not matches:
                print(Fore.YELLOW + "⚠ 正则表达式有效，但在data中没有找到匹配项" + Style.RESET_ALL)
                continue
            
            # 保存所有结果到result.txt
            with open(result_file, 'w', encoding='utf-8') as f:
                for match in matches:
                    if isinstance(match, tuple):
                        f.write(','.join(str(m) for m in match if m) + '\n')
                    else:
                        f.write(str(match) + '\n')
            
            # 清屏后显示结果
            clear_screen(data_file,result_file)
            print(Fore.MAGENTA + "=== 匹配结果 ===" + Style.RESET_ALL)
            
            # 显示文件前200个字符
            print(Fore.CYAN + "\n数据文件预览:" + Style.RESET_ALL)
            print(Fore.YELLOW + data[:200] + ("..." if len(data) > 200 else "") + Style.RESET_ALL)
            
            # 显示前20个匹配结果
            print(Fore.CYAN + f"\n前20个匹配结果(所有结果已保存到{result_file}):" + Style.RESET_ALL)
            for i, match in enumerate(matches[:20], 1):
                if isinstance(match, tuple):
                    print(Fore.BLUE + f"结果{i}: " + Fore.WHITE + f"{','.join(str(m) for m in match if m)}" + Style.RESET_ALL)
                else:
                    print(Fore.BLUE + f"结果{i}: " + Fore.WHITE + f"{match}" + Style.RESET_ALL)
            
            if len(matches) > 20:
                print(Fore.YELLOW + f"...还有{len(matches)-20}个结果未显示" + Style.RESET_ALL)
            
        except re.error as e:
            print(Fore.RED + f"✗ 正则表达式无效: {e}" + Style.RESET_ALL)
            print(Fore.YELLOW + "请重新输入或输入'exit'退出" + Style.RESET_ALL)

if __name__ == "__main__":
    validate_and_match_regex()
