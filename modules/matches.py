"""
matches.py - 匹配检测模块

这个模块提供了用于检测和匹配敏感信息的功能。
主要包含 MatchesPage 类，用于创建和管理匹配检测界面。
"""

import tkinter as tk
from tkinter import ttk
import threading
import re
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
from socketserver import ThreadingMixIn
import queue
import regex_rules
from urllib.parse import unquote,urlparse
import os
import subprocess


class MatchesPage(ttk.Frame):
    """
    匹配检测页面类
    
    提供用户界面来检测和显示敏感信息匹配结果。
    支持实时HTTP劫持和多种匹配规则。
    """
    # 初始化页面
    def __init__(self, parent, main_app):
        """
        初始化匹配检测页面
        
        Args:
            parent: 父级窗口组件
            main_app: 主应用程序实例
        """
        super().__init__(parent)
        # 保存主应用程序引用
        self.main_app = main_app

        # 获取当前主题current_directory
        self.current_theme = main_app.config.get('theme', '默认')
        self.current_directory = self.main_app.config.get('current_directory', '')
        self.python_path = self.main_app.config.get('python', '')

        # 初始化变量
        self.init_variables()

        # 创建界面
        self.create_widgets()
        
        # 配置样式
        self.setup_styles()
        
        # 创建任务队列
        self.task_queue = queue.Queue()
        # 标记是否继续处理
        self.processing = False
        # 工作线程
        self.worker_thread = None

    # 初始化变量
    def init_variables(self):
        # 初始化变量
        self.current_status = tk.StringVar(value="ALL")
        self.button_refs = None
        self.result_list = []
        self.server_running = False
        self.httpd = None
        self.js_data = []
        self.flag = [0, 0, 0, 0, 0]
        self.interfaces_analysing = False
        # self.bbdolt_file_path = os.getcwd()
        # 自定义域名列表
        self.self_define_domain_list = []

        
        # 将关键词列表定义为类属性
        self.first_keywords = ["Swagger UI", "云密钥", "企业微信密钥", "中国身份证号", "Java 反序列化", "Shiro Cookie", "Druid", "JDBC连接"]
        self.second_keywords = ["中国手机号", "JSON Web Token (JWT)", "URL 作为值", "授权头", "用户名字段", "手机号字段", "URL 字段", "敏感字段", "密码字段"]
        self.third_keywords = ["Ueditor", "PDF.js 查看器", "内网IP地址", "MAC地址", "上传表单", "Windows 文件/目录路径", "调试逻辑参数", "电子邮件", "JDBC连接"]
        self.fourth_keywords = ["域名提取", "绝对路径", "相对路径"]

    # 配置界面样式   
    def setup_styles(self):
        """配置界面样式"""
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12), padding=6)
        style.configure("Start.TButton", background="#4CAF50", foreground="white")
        style.configure("Stop.TButton", background="#f44336", foreground="white")
        self.apply_theme(self.current_theme)
        
    # 创建界面组件
    def create_widgets(self):
        """创建并布局界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self, padding=10, style="Border.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        main_frame.columnconfigure(0, weight=5)
        main_frame.columnconfigure(1, weight=0)
        main_frame.columnconfigure(2, weight=2)
        main_frame.rowconfigure(0, weight=1)
        
        # 输入框
        self.input_box = tk.Text(main_frame, wrap=tk.WORD, font=("Arial", 12))
        self.input_box.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # 下拉框
        self.domain_combobox = ttk.Combobox(main_frame, textvariable=self.current_status, 
                                     state="readonly", font=("Arial", 12))
        self.domain_combobox.grid(row=0, column=1, padx=5, pady=(0, 5), sticky="n")
        self.domain_combobox['values'] = ["ALL"]
        self.domain_combobox.set("ALL")
        self.domain_combobox.bind("<<ComboboxSelected>>", lambda event: self.update_output())

        # 添加域名过滤框
        add_domains_frame = ttk.Frame(main_frame)
        add_domains_frame.grid(row=0, column=1, sticky="nw", padx=5,pady=(30, 5))
        self.add_domains_entry = tk.Entry(add_domains_frame, width=23)
        self.add_domains_entry.grid(row=0, column=0, sticky="nw")
        self.add_domains_entry.default_text = "添加过滤域名"
        self.add_domains_entry.insert(0, self.add_domains_entry.default_text)
        self.add_domains_entry.config(fg='grey')
        self.add_domains_entry.bind("<FocusIn>", self.on_focus_in)
        self.add_domains_entry.bind("<FocusOut>", self.on_focus_out)

        # 添加“add”按钮
        self.add_button = tk.Button(add_domains_frame, text="+", width=4, font=("Arial", 7), command=self.set_domain_list)
        self.add_button.grid(row=0, column=1, padx=3)
        
        # 提取按钮
        self.extract_button = ttk.Button(main_frame, text="提取", 
                                       command=self.on_extract_click)
        self.extract_button.grid(row=0, column=1, padx=5, pady=5)
        # AI 分析接口按钮
        self.ai_analysis_button = ttk.Button(main_frame, text="AI接口分析", command=self.start_analysis_thread)
        self.ai_analysis_button.grid(row=0, column=1, padx=5, pady=(2, 105))
       
        # 右边加一个Frame，用来放输出框和滚动条
        output_frame = ttk.Frame(main_frame)
        output_frame.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        
        output_frame.rowconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)
        output_frame.columnconfigure(1, weight=0)
        output_frame.columnconfigure(2, weight=0)
        
        # 输出框
        self.output_box = tk.Text(output_frame, wrap=tk.WORD, font=("Arial", 12), 
                                 state=tk.DISABLED)
        self.output_box.grid(row=0, column=0, sticky="nsew")
        
        # 输出框的滚动条
        output_scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, 
                                       command=self.output_box.yview)
        output_scrollbar.grid(row=0, column=1, sticky="ns")
        self.output_box.config(yscrollcommand=output_scrollbar.set)
        
        # 配置标签颜色
        self.output_box.tag_configure("red_tag", foreground="red")
        self.output_box.tag_configure("orange_tag", foreground="orange")
        self.output_box.tag_configure("green_tag", foreground="green")
        self.output_box.tag_configure("gray_tag", foreground="gray")
        self.output_box.tag_configure("black_tag", foreground="black")
        
        # 右侧按钮栏
        button_panel = tk.Frame(output_frame, width=35)
        button_panel.grid(row=0, column=2, sticky="ns")
        button_panel.grid_propagate(False)
        button_panel.rowconfigure([0, 1, 2, 3, 4, 5], weight=1)
        
        button_texts = [("A\nL\nL", "ALL"),
                       ("高\n危", "red_tag"),
                       ("中\n危", "orange_tag"),
                       ("低\n危", "green_tag"),
                       ("路\n径", "black_tag"),
                       ("密\n钥", "gray_tag")]
        
        self.button_refs = []
        
        for i, (text, level) in enumerate(button_texts):
            btn = tk.Button(button_panel, text=text, font=("Arial", 12), 
                          justify="center",
                          command=lambda lvl=level: self.update_output(lvl))
            btn.grid(row=i, column=0, sticky="nsew", padx=2, pady=2)
            self.button_refs.append(btn)
        
        # 劫持按钮
        self.server_button = ttk.Button(main_frame, text="开始劫持", 
                                      command=self.toggle_server, style="Start.TButton")
        self.server_button.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        # 清空按钮
        clear_button = ttk.Button(main_frame, text="清空结果", 
                                command=self.clear_output)
        clear_button.grid(row=1, column=2, padx=5, pady=5, sticky="e")
        
    # 切换HTTP服务器状态
    def toggle_server(self):
        """切换HTTP服务器状态"""
        if not self.server_running:
            self.server_thread = threading.Thread(target=self.start_http_server, daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.server_button.config(text="关闭劫持", style="Stop.TButton")
            
            # 启动队列处理线程
            self.processing = True
            self.worker_thread = threading.Thread(target=self.process_queue, daemon=True)
            self.worker_thread.start()
            
            # 注册HTTP服务器资源
            self.main_app.register_resource(
                "matches_http_server",
                self.cleanup_server
            )
            
            # 注册队列处理器
            self.main_app.register_resource(
                "matches_queue_processor",
                self.cleanup_queue_processor
            )
            
        else:
            self.cleanup_server()
            self.cleanup_queue_processor()
            self.main_app.unregister_resource("matches_http_server")
            self.main_app.unregister_resource("matches_queue_processor")
            self.server_button.config(text="开始劫持", style="Start.TButton")
            
    # 处理队列中的任务
    def process_queue(self):
        """处理队列中的任务"""
        while self.processing:
            while self.interfaces_analysing:
                pass
            try:
                # 从队列获取任务，设置超时以便能够响应关闭请求
                url, body_text, response_len = self.task_queue.get(timeout=1)
                self.extract_thread(url, body_text, response_len)
                self.task_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"处理队列任务时出错: {str(e)}")
                
    # 清理队列处理器
    def cleanup_queue_processor(self):
        """清理队列处理器"""
        self.processing = False
        
        # 等待工作线程完成
        if self.worker_thread and self.worker_thread.is_alive():
            try:
                self.worker_thread.join(timeout=5)
            except Exception as e:
                print(f"等待队列处理线程时出错: {str(e)}")
        
        # 清空队列
        while not self.task_queue.empty():
            try:
                self.task_queue.get_nowait()
                self.task_queue.task_done()
            except:
                pass
            
    # 清理HTTP服务器资源
    def cleanup_server(self):
        """清理HTTP服务器资源"""
        if self.httpd:
            self.server_running = False
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception as e:
                print(f"关闭HTTP服务器时出错: {str(e)}")
            finally:
                self.httpd = None
    
    # 启动HTTP服务器
    def start_http_server(self):
        """启动HTTP服务器"""
        class RequestHandler(BaseHTTPRequestHandler):
            parent = self
            
            # 判断是不是 js 链接
            def is_js_file(self, url):
                return re.search(r'\.js($|\?|#)', url, re.IGNORECASE) is not None
            # 获取
            def get_url_main_path(self, url):
                path = url.split('?', 1)[0].split('#', 1)[0]
                return path.rstrip('/')
            def is_static_file(self, url: str) -> bool:
                """检查 URL 中是否包含静态文件扩展名（不再要求必须在结尾）"""
                lower_url = url.lower()
                print(lower_url,any(ext in lower_url for ext in regex_rules.static_file_extensions))
                return any(ext in lower_url for ext in regex_rules.static_file_extensions)
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
                
                # 快速响应
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
                
                try:
                    data = json.loads(body)
                    url = data.get('url', '')
                    body_text = data.get('body', '')
                    
                    # 解码URL
                    url_base64_decoded = base64.b64decode(url)  # 保留原始字节数据
                    try:
                        url_decoded = unquote(url_base64_decoded.decode('utf-8'))
                    except UnicodeDecodeError as decode_err:
                        print(f"URL解码失败: {decode_err}，继续使用base64解码后的原始数据")
                        url_decoded = unquote(url_base64_decoded.decode('latin-1'))  # 使用latin-1兼容所有字节
                    except Exception as e:
                        print(f"URL处理意外错误: {e}")
                        url_decoded = str(url_base64_decoded)  # 回退方案

                    # 解码Body
                    body_base64_decoded = base64.b64decode(body_text)  # 保留原始字节数据
                    try:
                        body_text_decoded = unquote(body_base64_decoded.decode('utf-8'))
                    except UnicodeDecodeError as decode_err:
                        print(f"Body解码失败: {decode_err}，继续使用base64解码后的原始数据")
                        body_text_decoded = unquote(body_base64_decoded.decode('latin-1'))  # 使用latin-1兼容所有字节
                    except Exception as e:
                        print(f"Body处理意外错误: {e}")
                        body_text_decoded = str(body_base64_decoded)  # 回退方案

                    response_len = str(len(body_base64_decoded))
                    main_path = self.get_url_main_path(url_decoded)
                    
                    if not self.is_static_file(main_path):
                        if self.is_js_file(main_path):
                            if main_path not in self.parent.js_data:
                                self.parent.js_data.append(main_path)
                                self.parent.task_queue.put((url_decoded, body_text_decoded, response_len))
                                # print(main_path.split('/')[-1])
                        else:
                            self.parent.task_queue.put((url_decoded, body_text_decoded, response_len))
                            # print(main_path.split('/')[-1])
                            
                except Exception as e:
                    print("do_POST 函数内报错", e)

                    
            def log_message(self, format, *args):
                pass
                
        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True
            
        server_address = ('127.0.0.1', self.main_app.config.get('http_port', 9015))
        try:
            self.httpd = ThreadingHTTPServer(server_address, RequestHandler)
            self.httpd.serve_forever()
        except Exception as e:
            print(f"HTTP服务器启动失败: {str(e)}")
            self.cleanup_server()

    def extract_uri(self, url):
        """
        从完整URL中提取URI部分（包含路径、查询参数和片段标识）
        示例: 
        输入: "https://example.com/test?sdf=1#section" 
        输出: "/test?sdf=1#section"
        如果URL路径以静态扩展名结尾，直接返回0
        """
        parsed = urlparse(url)
        keep_params = True
        if len(url) > 100:
            keep_params = False
        # 首先检查路径部分是否以静态扩展名结尾
        path = parsed.path.lower()  # 转为小写方便比较
        
        if any(path.endswith(ext) for ext in regex_rules.static_extension):
            return 0
        
        # 组合路径、查询参数和片段标识
        uri = parsed.path
        if parsed.query and keep_params:
            uri += '?' + parsed.query
        if parsed.fragment and keep_params:
            uri += '#' + parsed.fragment
        return uri

    # 提取匹配结果的线程函数
    def extract_thread(self, url="", body="", response_len="-"):
        """
        提取匹配结果的线程函数
        
        Args:
            url: 目标URL
            body: 要分析的内容
        """
        self.extract_button.config(state=tk.DISABLED, text="提取中...")
        self.ai_analysis_button.config(state=tk.DISABLED)
        # input_text = self.input_box.get("1.0", tk.END)
        
        # if url == "" and body == "":
        #     matched, errors = self.match_rules(input_text)
        # else:
        matched, errors = self.match_rules(body)
        if errors != []:
            print("报错信息列表", errors)
                
        # 整理结果
        new_results = []
        if url == "":
            for text, rule_name in matched:
                new_results.append(f"{text}  ({rule_name})  no_url  [-]")
        else:
            for text, rule_name in matched:
                new_results.append(f"{text}  ({rule_name})  {url}  [-]")
            extract_uri_1 = self.extract_uri(url)
            if extract_uri_1 != 0 and extract_uri_1 != "/":
                new_results.append(f"{extract_uri_1}  绝对路径  {url}  {response_len}")
        # new_results.extend(errors)
        
        # 过滤空白结果和"无匹配"
        valid_results = [x for x in new_results if x and x != '无匹配']
        
        # 使用集合操作找出新的结果
        current_set = set(self.result_list)
        new_set = set(valid_results)
        truly_new_results = new_set - current_set
        
        # 如果有新结果，更新列表并刷新显示
        if truly_new_results:
            self.result_list.extend(truly_new_results)
            self.update_output()
        
        self.extract_button.config(state=tk.NORMAL, text="提取")
        self.ai_analysis_button.config(state=tk.NORMAL)
        
    # 应用规则进行匹配
    def match_rules(self, text):
        """
        应用规则进行匹配
        
        Args:
            text: 要匹配的文本
            
        Returns:
            tuple: (匹配结果列表, 错误列表)
        """
        matched_data = []
        errors = []
        
        # HaE 正则表达式匹配敏感信息
        for rule in regex_rules.HaE_rules:
            rule_name = rule['VerboseName']
            pattern_str = rule['Rule']
            try:
                pattern = re.compile(pattern_str)
                for match in pattern.finditer(text):
                    matched_text = match.group()
                    matched_text = matched_text.replace("\'","").replace("\"","")
                    matched_data.append((matched_text, rule_name))
            except re.error as e:
                errors.append(f"规则错误: {rule_name} ({e})")
        
        # nuclei_regex 正则表达式 Secret
        for rule in regex_rules.nuclei_regex:
            rule_name = rule['VerboseName']
            pattern_str = rule['Rule']
            try:
                pattern = re.compile(pattern_str)
                for match in pattern.finditer(text):
                    matched_text = match.group()
                    matched_text = matched_text.replace("\'","").replace("\"","")
                    matched_data.append((matched_text, rule_name))
            except re.error as e:
                errors.append(f"规则错误: {rule_name} ({e})")

        for rule in regex_rules.path_rules:
            rule_name = rule['VerboseName']      # 取出规则的名字（用于标识规则）
            pattern_str = rule['Rule']           # 取出规则的正则表达式字符串
            try:
                pattern = re.compile(pattern_str)    # 编译正则表达式
                for match in pattern.finditer(text): # 在目标文本text中查找所有匹配项
                    matched_text = match.group()     # 获取匹配到的文本内容
                    matched_text = matched_text.replace("\'","").replace("\"","")
                    
                    # Handle long URLs with parameters
                    if len(matched_text) > 100:
                        # Split at first ? to remove parameters
                        base_path = matched_text.split('?')[0]
                        if len(base_path) <= 100:
                            matched_text = base_path
                        else:
                            # Skip if even without parameters it's too long
                            continue
                    
                    # 判断是否包含静态文件后缀
                    if not any(ext in matched_text.lower() for ext in regex_rules.static_extension) and "./" not in matched_text and matched_text not in regex_rules.exclude_content:
                        matched_data.append((matched_text, rule_name))  # 只添加不包含静态资源后缀的内容
            except re.error as e:
                errors.append(f"规则错误: {rule_name} ({e})")  # 如果正则表达式有语法错误，记录错误信息


        return matched_data, errors
        
    # 根据行内容确定标签类型
    def get_tag_by_line(self, line):
        """
        根据行内容确定标签类型
        
        Args:
            line: 要分析的行文本
            
        Returns:
            str: 标签类型
        """
        if any(keyword in line for keyword in self.first_keywords):
            return "red_tag"
        elif any(keyword in line for keyword in self.second_keywords):
            return "orange_tag"
        elif any(keyword in line for keyword in self.third_keywords):
            return "green_tag"
        elif any(keyword in line for keyword in self.fourth_keywords):
            return "black_tag"
        else:
            return "gray_tag"
            
    # 更新输出显示
    def update_output(self, button="ALL"):
        """
        更新输出显示
        
        Args:
            button: 按钮类型，默认为"ALL"
        """
        self.flag = [0, 0, 0, 0, 0]  # 记录各类型数量
        
        self.output_box.config(state=tk.NORMAL)
        self.output_box.delete("1.0", tk.END)

        is_path_special = False
        if button == "black_tag":
            is_path_special = True
            domain_list = []
            juedui_path = []
            xinagdui_path = []
        
        # 根据当前选择过滤结果
        filtered_results = []
        if self.current_status.get() != "ALL":
            filtered_results = [line for line in self.result_list 
                             if self.current_status.get() in line]
        else:
            filtered_results = self.result_list
        
            
        # 根据按钮类型进一步过滤
        if button != "ALL":
            display_results = []
            for line in filtered_results:
                tag = self.get_tag_by_line(line)
                if tag == button:
                    if is_path_special:
                        if "域名提取" in line:
                            liness = line.split('  ')
                            # if len(liness) == 4:
                            #     line = liness[0].replace('\'', '').replace('\"', '') + f"  [{liness[3]}]"
                            #     line = line.replace("[[","[").replace("]]",']')
                            domain_list.append(liness[0].replace('\'', '').replace('\"', ''))
                        elif "绝对路径" in line:
                            liness = line.split('  ')
                            # if len(liness) == 4:
                            #     line = liness[0].replace('\'', '').replace('\"', '') + f"  [{liness[3]}]"
                            #     line = line.replace("[[","[").replace("]]",']')
                            juedui_path.append(liness[0].replace('\'', '').replace('\"', ''))
                        else:
                            liness = line.split('  ')
                            # if len(liness) == 4:
                            #     line = liness[0].replace('\'', '').replace('\"', '') + f"  [{liness[3]}]"
                            #     line = line.replace("[[","[").replace("]]",']')
                            xinagdui_path.append(liness[0].replace('\'', '').replace('\"', ''))
                        continue
                    else:
                        display_results.append(line)
                else:
                    self.update_flag_count(tag)
        else:
            display_results = filtered_results
        if is_path_special:
            # 去重
            juedui_path = list(set(juedui_path))
            xinagdui_path = list(set(xinagdui_path))
            domain_list = list(set(domain_list))
            self.flag[3] = len(xinagdui_path) + len(juedui_path) + len(domain_list)
            self.output_box.insert(tk.END, "绝对路径：\n", "black_tag")
            for line in juedui_path:
                self.output_box.insert(tk.END, line + "\n", "black_tag")
            self.output_box.insert(tk.END, "\n")
            self.output_box.insert(tk.END, "相对路径：\n", "black_tag")
            for line in xinagdui_path:
                if line in regex_rules.exclude_content:
                    continue
                if "./" in line:
                    continue
                self.output_box.insert(tk.END, line + "\n", "black_tag")
            self.output_box.insert(tk.END, "\n")
            self.output_box.insert(tk.END, "域名提取：\n", "black_tag")
            for line in domain_list:
                self.output_box.insert(tk.END, line + "\n", "black_tag")
        # 显示结果
        if display_results:
            # print(len(display_results))
            for line in display_results:
                tag = self.get_tag_by_line(line.replace('\'', '').replace('\"', ''))
                self.update_flag_count(tag)
                self.output_box.insert(tk.END, line + "\n\n", tag)
        else:
            if not is_path_special:
                self.output_box.insert(tk.END, "无匹配\n", "gray_tag")
            
        # 更新按钮文本
        self.refresh_button_counts(len(filtered_results))
        # print(len(filtered_results))
        
        # 刷新域名列表
        self.refresh_domains()
        
        self.output_box.config(state=tk.DISABLED)
        
    # 更新标志计数
    def update_flag_count(self, tag):
        """
        更新标志计数
        
        Args:
            flag: 标志计数列表
            tag: 标签类型
        """
        if tag == "red_tag":
            self.flag[0] += 1
        elif tag == "orange_tag":
            self.flag[1] += 1
        elif tag == "green_tag":
            self.flag[2] += 1
        elif tag == "black_tag":
            self.flag[3] += 1
        else:
            self.flag[4] += 1
            
    # 刷新按钮计数显示
    def refresh_button_counts(self, total):
        """
        刷新按钮计数显示
        
        Args:
            flag: 标志计数列表
            total: 总数
        """
        self.button_refs[0].config(text=f"A\nL\nL\n\n{total}")
        self.button_refs[1].config(text=f"高\n危\n\n{self.flag[0]}")
        self.button_refs[2].config(text=f"中\n危\n\n{self.flag[1]}")
        self.button_refs[3].config(text=f"低\n危\n\n{self.flag[2]}")
        self.button_refs[4].config(text=f"路\n径\n\n{self.flag[3]}")
        self.button_refs[5].config(text=f"密\n钥\n\n{self.flag[4]}")
        
    # 刷新域名列表
    def refresh_domains(self):
        """刷新域名列表"""
        domains = set()
        for line in self.result_list:
            parts = line.split("  ")
            if len(parts) > 2:
                domain = parts[2].replace("https://", "").replace("http://", "")
                domain = domain.split("/")[0]
                domains.add(domain)
        domain_list = sorted(list(domains))
        domain_list.insert(0, "ALL")
        domain_list.extend(self.self_define_domain_list)
        self.domain_combobox['values'] = domain_list
        self.domain_combobox.set(self.current_status.get())
        
    # 处理提取按钮点击事件
    def on_extract_click(self):
        """处理提取按钮点击事件"""
        # 使用队列来处理手动提取
        if self.processing:
            self.task_queue.put(("", self.input_box.get("1.0", tk.END),'[-]'))
        else:
            threading.Thread(target=self.extract_thread, args=('',self.input_box.get("1.0", tk.END))).start()
              
    # 清空输出结果
    def clear_output(self):
        """清空输出结果"""
        self.js_data = []
        self.result_list = []
        self.current_status.set("ALL")
        self.domain_combobox['values'] = ["ALL"]
        self.domain_combobox.set(self.current_status.get())
        self.flag = [0, 0, 0, 0, 0]
        self.refresh_button_counts(0)
        self.output_box.config(state=tk.NORMAL)
        self.output_box.delete("1.0", tk.END)
        self.output_box.config(state=tk.DISABLED)

    # 应用指定的主题样式
    def apply_theme(self, theme_name):
        """
        应用指定的主题样式
        
        Args:
            theme_name: 主题名称（'默认'、'粉色'、'浅蓝'或'浅色'）
        """
        # style = ttk.Style()
        
        # 重置原有标签颜色
        if theme_name == '粉色':
            self.output_box.tag_configure("red_tag", foreground="#FF0055")  # 更亮的红色
            self.output_box.tag_configure("orange_tag", foreground="#FF6D00")  # 更亮的橙色
            self.output_box.tag_configure("green_tag", foreground="#00CC66")  # 更亮的绿色
            self.output_box.tag_configure("gray_tag", foreground="#9370DB")  # 淡紫色代替灰色
            self.output_box.tag_configure("black_tag", foreground="black")
            
            # 按钮样式
            for btn in self.button_refs:
                btn.configure(background="#FFB6C1", foreground="#FF1493")
                
        elif theme_name == '浅蓝':
            self.output_box.tag_configure("red_tag", foreground="#E74C3C")  # 鲜红色
            self.output_box.tag_configure("orange_tag", foreground="#F39C12")  # 橙黄色
            self.output_box.tag_configure("green_tag", foreground="#27AE60")  # 祖母绿
            self.output_box.tag_configure("gray_tag", foreground="#7F8C8D")  # 青灰色
            self.output_box.tag_configure("black_tag", foreground="black")
            
            # 按钮样式
            for btn in self.button_refs:
                btn.configure(background="#BBE1FF", foreground="#1E6CB0")
                
        elif theme_name == '浅色':
            self.output_box.tag_configure("red_tag", foreground="#c0392b")  # 暗红色
            self.output_box.tag_configure("orange_tag", foreground="#d35400")  # 砖橙色
            self.output_box.tag_configure("green_tag", foreground="#16a085")  # 深绿色
            self.output_box.tag_configure("gray_tag", foreground="#7f8c8d")  # 深灰色
            self.output_box.tag_configure("black_tag", foreground="black")
            
            # 按钮样式
            for btn in self.button_refs:
                btn.configure(background="#bdc3c7", foreground="#2c3e50")
                
        else:  # 默认主题
            self.output_box.tag_configure("red_tag", foreground="red")
            self.output_box.tag_configure("orange_tag", foreground="orange")
            self.output_box.tag_configure("green_tag", foreground="green")
            self.output_box.tag_configure("gray_tag", foreground="gray")
            self.output_box.tag_configure("black_tag", foreground="black")
            
            # 按钮样式
            for btn in self.button_refs:
                btn.configure(background="#e0e0e0", foreground="#333333")
        
        # 根据当前结果刷新显示
        # self.update_output()

    # 接口分析处理
    def start_analysis_thread(self):
        # 创建并启动线程
        self.extract_button.config(state=tk.DISABLED)
        self.ai_analysis_button.config(state=tk.DISABLED)
        self.interfaces_analysing = True
        thread = threading.Thread(target=self.interfaces_analysis, daemon=True)
        thread.start()

    def interfaces_analysis(self):
        """
        [
            {"uri": "/getUser?id=1"},
            {"uri": "/memberlists?pageNo=1&pageSize=10", "response_size": 1200},
            {"uri": "/login.action"},
        ]
        """
        interfaces_analysis_text = ""
        # 使用 os.path.join 来拼接文件路径，确保路径的正确性
        text_filepath = os.path.join(self.current_directory, "Tools", "Interface_analysis", "text.txt")
        analysis_py_file = os.path.join(self.current_directory, "Tools", "Interface_analysis", "Interface_analysis.py")
        analysis_py_directory = os.path.dirname(analysis_py_file)
        domaining = self.current_status.get()
        

        for iiai in self.result_list:
            if "绝对路径" in iiai and (domaining in iiai or domaining == "ALL"):
                iiaiss = iiai.split('  ')
                if len(iiaiss) == 4:
                    line = "{},{},{}".format(
                        iiaiss[0].replace("'", "").replace('"', ''),
                        iiaiss[3].replace("[-]","-1"),
                        iiaiss[2]
                    )
                    line = line + "\n"
                    interfaces_analysis_text += line
                else:
                    print("matches.py 第 787 行报错")

        # 将内容写入文件
        try:
            with open(text_filepath, 'w', encoding='utf-8') as file:
                file.write(interfaces_analysis_text)
            print(f"接口分析结果已成功写入文件: {text_filepath}")
        except Exception as e:
            print(f"写入文件时发生错误: {e}")
        if self.main_app.config.get("ai_analysis_next"):
            cmd = f'start "" cmd /k "{self.python_path} {analysis_py_file} -r {text_filepath} -o - -n"'
        else:
            cmd = f'start "" cmd /k "{self.python_path} {analysis_py_file} -r {text_filepath} -o -"'
        try:
            subprocess.Popen(cmd, cwd=analysis_py_directory, shell=True)
        except:
            print("启动接口分析进程失败")

        self.interfaces_analysing = False
        self.extract_button.config(state=tk.NORMAL)
        self.ai_analysis_button.config(state=tk.NORMAL)

    def on_focus_in(self, event):
        """通用获得焦点事件处理"""
        widget = event.widget
        default_text = widget.default_text  # 从widget属性获取预设文本
        if widget.get() == default_text:
            widget.delete(0, tk.END)
            widget.config(fg='black')

    def on_focus_out(self, event):
        """通用失去焦点事件处理"""
        widget = event.widget
        default_text = widget.default_text
        if not widget.get():
            widget.insert(0, default_text)
            widget.config(fg='grey')
        else:
            widget.config(fg='black')    

    def set_domain_list(self):
        new_domain = self.add_domains_entry.get().strip()
        if "添加过滤域名" in new_domain or new_domain in self.self_define_domain_list:
            return
        else:
            self.self_define_domain_list.append(new_domain)
            self.refresh_domains()

# 创建匹配检测页面实例
def create_matches_page(parent, main_app):
    """
    创建匹配检测页面实例
    
    Args:
        parent: 父级窗口组件
        main_app: 主应用程序实例
        
    Returns:
        MatchesPage: 匹配检测页面实例
    """
    return MatchesPage(parent, main_app)