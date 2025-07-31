"""
find_path.py - 提取接口信息模块

这个模块提供了用于提取接口信息的功能。
主要包含 FindPathPage 类，用于创建和管理提取接口信息界面。
"""

import tkinter as tk
from tkinter import ttk
import threading
import subprocess
from tkinter import messagebox
import re
import regex_rules
import os
from urllib.parse import urlparse
import regex_rules
from urllib.parse import urlparse
from tkinter import filedialog
import requests

class FindPathPage(ttk.Frame):
    """
    提取接口信息类
    
    提取Js文件中的接口信息
    """
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
        self.current_theme = main_app.config.get('theme', '默认')

        # 初始化变量
        self.init_variables()
        # 创建界面
        self.create_widgets()
        # 配置样式
        self.setup_styles()

    def init_variables(self):
        self.packerfuzzer_proc = None
        self.url = ""
        # 获取配置信息
        self.packer_dir = self.main_app.config.get("packerfuzzer")
        self.python_path = self.main_app.config.get("python")
        self.file_packerfuzzer_path = os.path.join(self.packer_dir, "PackerFuzzer.py")
        self.tmp_dir_path = os.path.join(self.packer_dir, "tmp")
        # 将关键词列表定义为类属性
        self.first_keywords = ["Swagger UI", "云密钥", "企业微信密钥", "中国身份证号", "Java 反序列化", "Shiro Cookie", "Druid", "JDBC连接"]
        self.second_keywords = ["中国手机号", "JSON Web Token (JWT)", "URL 作为值", "授权头", "用户名字段", "手机号字段", "URL 字段", "敏感字段", "密码字段"]
        self.third_keywords = ["Ueditor", "PDF.js 查看器", "内网IP地址", "MAC地址", "上传表单", "Windows 文件/目录路径", "调试逻辑参数", "电子邮件", "JDBC连接"]
        self.fourth_keywords = ["域名提取", "绝对路径", "相对路径"]
        # 保存结果 result_list
        self.result_list = []
        # 初始化标记位
        self.flag = [0,0,0,0,0]

    def create_widgets(self):
        # 创建主框架
        self.main_frame = ttk.Frame(self, padding="10", style="Border.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 规划网格布局
        self.main_frame.columnconfigure(0, weight=2)
        self.main_frame.columnconfigure(1, weight=3)
        self.main_frame.rowconfigure(0, weight=1)


        # url 输入处理部分
        self.url_process_frame = ttk.LabelFrame(self.main_frame, text=" url 处理 ", padding="3", style="Border.TFrame")
        self.url_process_frame.grid(row=0, column=0, sticky="new", padx=(3,0))
        # 让第0列可以拉伸
        self.url_process_frame.columnconfigure(0, weight=1)


        # 在 create_widgets 里调用
        self.input_box_url = tk.Entry(self.url_process_frame, font=("Arial", 12), width=40)
        self.input_box_url.grid(row=0, column=0, sticky="new", padx=(0, 5), pady=(5,10))
        self.set_entry_placeholder(self.input_box_url, "http://www.xxxxx.com")

        # 在__init__或create_widgets中初始化按钮
        self.scan_button = ttk.Button(self.url_process_frame, text="开始扫描", command=self.toggle_scan, style="Start.TButton")
        self.scan_button.grid(row=0, column=0, sticky="nw", padx=(0,3), pady=(35, 0))

        self.open_reports_btn = tk.Button(
            self.url_process_frame,
            text="打开报告夹",
            font=("Arial", 13),
            justify="center",
            command=lambda: self.open_reports_folder()
        )
        self.open_reports_btn.grid(row=0, column=0, sticky="nw", padx=(220,3), pady=(35, 0))
        # 文件处理部分
        self.files_process_frame = ttk.LabelFrame(self.main_frame, text=" 文件/文件夹处理（可选择文件/文件夹） ", padding="3", style="Border.TFrame")
        self.files_process_frame.grid(row=0, column=0, sticky="new", padx=(3,0), pady=(120,0))
        
        # 扫描按钮
        self.scan_file_button = tk.Button(
            self.files_process_frame,
            text="开始文件夹扫描",
            command=lambda: self.extract_Js_info_having_thread(0)
        )
        self.scan_file_button.grid(row=0, column=0, sticky="ne", padx=(228,3), pady=(5, 0))
        self.scan_files_button = tk.Button(
            self.files_process_frame,
            text="开始文件扫描",
            command=lambda: self.extract_Js_info_having_thread(1)
        )
        self.scan_files_button.grid(row=0, column=0, sticky="nw", padx=(0,3), pady=(5, 0))

        # # 进度条部分
        # self.step_process_frame = ttk.LabelFrame(self.main_frame, text=" 进度显示 ", padding="3", style="Border.TFrame")
        # self.step_process_frame.grid(row=0, column=0, sticky="new", padx=(3,0), pady=(200,0))

        # 输出框部分
        output_frame = ttk.Frame(self.main_frame)
        output_frame.grid(row=0, column=1, sticky="nse", padx=(15, 0))
        # output 部分的网格布局
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

    def setup_styles(self):
        style = ttk.Style()
        style.configure("Start.TButton", background="#4CAF50", foreground="white")
        style.configure("Stop.TButton", background="#f44336", foreground="white")
        self.apply_theme(self.current_theme)

    def run_packer_fuzzer(self, url):
        def task():
            # 检查路径是否都存在
            if not os.path.exists(self.file_packerfuzzer_path):
                self.after(0, lambda: messagebox.showerror("错误", "PackerFuzzer.py 文件不存在"))
                return
            if not os.path.exists(self.python_path):
                self.after(0, lambda: messagebox.showerror("错误", "python 路径不存在"))
                return         
            # 检查是深度测试、还是普通测试
            if self.main_app.config.get("deep_scan_packerfuzzer"):
                cmd = [self.python_path, self.file_packerfuzzer_path, "-u", url] + self.main_app.config.get("deep_scan", [])
                print(cmd)
            else:
                cmd = [self.python_path, self.file_packerfuzzer_path, "-u", url] + self.main_app.config.get("easy_scan", [])
                print(cmd)

            # 开始尝试运行提取接口
            try:
                # 注册需要清理的资源
                self.main_app.register_resource("packerfuzzer_proc", self.cleanup_scan_thread)
                # 用Popen启动进程，并保存到self
                print("开始爬取 Js 文件")
                self.url_process_frame.config(text=" 开始爬取 Js 文件... ")
                self.packerfuzzer_proc = subprocess.Popen(cmd, cwd=self.packer_dir)
                self.packerfuzzer_proc.wait()
                self.main_app.unregister_resource("packerfuzzer_proc")
                # 开始提取 Js 文件中的内容（默认的文件会放置在 packer_dir目录 tmp 文件夹下）
                print("开始提取 Js 文件中的敏感信息")
                self.url_process_frame.config(text=" 开始提取 Js 文件中的敏感信息... ")
                self.extract_Js_info_url(url)
                self.main_app.unregister_resource("packerfuzzer_proc")
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", f"扫描失败: {e}"))
            finally:
                self.after(0, lambda: self.scan_button.config(text="开始扫描", style="Start.TButton"))
                self.url_process_frame.config(text=" url 处理 ")
                self.packerfuzzer_proc = None

        if self.packerfuzzer_proc is None:
            threading.Thread(target=task, daemon=True).start()
        else:
            threading.Thread(target=self.cleanup_scan_thread, daemon=True).start()
    
    # 清理扫描线程
    def cleanup_scan_thread(self):
        # 检查进程是否存在且还在运行
        if hasattr(self, "packerfuzzer_proc") and self.packerfuzzer_proc is not None:
            try:
                self.packerfuzzer_proc.terminate()  # 发送终止信号
                self.packerfuzzer_proc.wait(timeout=5)  # 等待进程结束
                self.packerfuzzer_proc = None
                # messagebox.showinfo("提示", "扫描已被终止！")
            except Exception as e:
                messagebox.showerror("错误", f"终止失败: {e}")
            finally:
                self.scan_button.config(text="开始扫描", style="Start.TButton")
                self.main_app.unregister_resource("packerfuzzer_proc")
        else:
            pass
            # messagebox.showinfo("提示", "没有正在运行的扫描进程。")
    
    # 切换扫描状态
    def toggle_scan(self):
        if getattr(self, "packerfuzzer_proc", None) is None:
            # 没有进程，开始扫描
            if self.input_box_url.get() == "http://www.xxxxx.com":
                self.after(0, lambda: messagebox.showerror("错误", "请不要使用默认 url"))
                return
            if not self.is_valid_url(self.input_box_url.get()):
                self.after(0, lambda: messagebox.showerror("错误", "url 格式错误"))
                return
            if self.is_js_url(self.input_box_url.get()):
                threading.Thread(target=self.extract_js_url_info, args=(self.input_box_url.get(),), daemon=True).start()
                return
            self.run_packer_fuzzer(self.input_box_url.get())
            self.scan_button.config(text="终止扫描", style="Stop.TButton")
        else:
            # 有进程，终止扫描
            self.cleanup_scan_thread()
            self.scan_button.config(text="开始扫描", style="Start.TButton")
            self.url_process_frame.config(text=" url 处理 ")

    # 开始提取 Js 文件中的信息
    def extract_Js_info_url(self, url):
        self.result_list = []
        parsed = urlparse(url)
        Js_path = parsed.hostname
        if parsed.port != None:
            Js_path += "_" + parsed.port
        
        js_files = self.collect_unique_js_files(Js_path)
        # 开始提取敏感信息到 matched_data 列表中
        for i, jsfile in enumerate(js_files):
            if hasattr(self, "packerfuzzer_proc") and self.packerfuzzer_proc is None:
                return
            self.url_process_frame.config(text=f" 开始提取 Js 文件中的敏感信息...（{i}/{len(js_files)}）")
            try:
                with open(jsfile, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # 开始匹配规则，返回匹配内容列表与报错列表
                    matched, errors = self.match_rules(content)
                    # 合并到总的列表中
                    self.result_list.extend(matched)
            except Exception as e:
                print(f"读取文件 {jsfile} 失败: {e}")
        # 进行去重，保存结果
        self.result_list = list(set(self.result_list))
        self.update_output()
            
    # 提取 tmp 目录下的指定域名 Js 文件（只选js文件最多的文件夹）
    def collect_unique_js_files(self, js_path):
        max_js_count = 0
        target_js_files = []

        # 遍历 tmp_dir_path 下所有文件夹
        for root, dirs, files in os.walk(self.tmp_dir_path):
            if js_path in os.path.basename(root):
                js_files = [os.path.join(root, file) for file in files if file.endswith('.js')]
                if len(js_files) > max_js_count:
                    max_js_count = len(js_files)
                    target_js_files = js_files

        return target_js_files
        
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
                    matched_data.append((matched_text, rule_name))
            except re.error as e:
                errors.append(f"规则错误: {rule_name} ({e})")

        # 匹配路径信息
        for rule in regex_rules.path_rules:
            rule_name = rule['VerboseName']
            pattern_str = rule['Rule']
            try:
                pattern = re.compile(pattern_str)
                for match in pattern.finditer(text):
                    matched_text = match.group()
                    # 判断是否是有效接口
                    if not any(ext in matched_text.lower() for ext in regex_rules.static_extension):
                        matched_data.append((matched_text, rule_name))
            except re.error as e:
                errors.append(f"规则错误: {rule_name} ({e})")
                
        return matched_data, errors  

    # 提取单个文件/文件夹线程
    def extract_Js_info_having_thread(self, choice):
        if getattr(self, "packerfuzzer_proc", None) is not None:
            self.after(0, lambda: messagebox.showerror("错误", "请先关闭 url 扫描"))
            return
        if choice:
            path = filedialog.askopenfilename(
                title="选择JS文件或文件夹",
                filetypes=[("JavaScript文件", "*.js"), ("所有文件", "*.*")]
            )
        else:
            path = filedialog.askdirectory(title="选择文件夹")
        threading.Thread(target=self.extract_Js_info_having, args=(path,), daemon=True).start()
        
    # 提取已存在文件或文件夹
    def extract_Js_info_having(self, any_path):
        print("开始获取 Js 文件...")
        self.files_process_frame.config(text="开始获取 Js 文件...")
        self.result_list = []
        is_file = os.path.isfile(any_path)
        js_files = []
        # 获取 js 文件列表
        if is_file:
            js_files.append(any_path)
        else:
            # 递归遍历文件夹及所有子文件夹
            for root, dirs, files in os.walk(any_path):
                for file in files:
                    if file.endswith(".js"):
                        js_files.append(os.path.join(root, file))
        print("开始提取 js 中的敏感信息...")
        self.files_process_frame.config(text="开始提取 js 中的敏感信息...")
        # 开始提取所有 js 文件信息
        for i, jsfile in enumerate(js_files):
            try:
                self.files_process_frame.config(text=f"开始提取 js 中的敏感信息...（{i}/{len(js_files)}）")
                with open(jsfile, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    matched, errors = self.match_rules(content)
                    self.result_list.extend(matched)

            except Exception as e:
                print(f"读取文件 {jsfile} 失败: {e}")
        self.result_list = list(set(self.result_list))
        self.update_output()
        self.files_process_frame.config(text=" 文件/文件夹处理（可选择文件/文件夹） ")

    # 提取 js_url 链接中的敏感信息
    def extract_js_url_info(self, url):
        self.result_list = []
        try:
            # 设置超时时间为10秒
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # 如果状态码不是200，会抛出HTTPError异常

            # 获取内容
            content = response.text
            matched, errors = self.match_rules(content)
            self.result_list.extend(matched)
        except requests.exceptions.Timeout:
            print("请求超时，请检查网络连接或服务器状态。")
        except requests.exceptions.RequestException as e:
            print(f"请求失败：{e}")
        self.result_list = list(set(self.result_list))
        self.update_output()

    # 更新输出框
    def update_output(self, button="ALL"):
        """
        更新输出界面

        Args:
            button: 按钮类型，默认为"ALL"
        """
        # 禁止点击任何该界面的按钮
        for btn in self.button_refs:
            btn.configure(state=tk.DISABLED)

        self.flag = [0,0,0,0,0]
        self.output_box.config(state=tk.NORMAL)
        self.output_box.delete("1.0", tk.END)
        display_result = []
        is_black_tag = False
        if button == "black_tag":
            is_black_tag = True
            domain_list = []
            juedui_path = []
            xinagdui_path = []
        
        # 根据按钮类型进一步过滤
        if button != "ALL" and not is_black_tag:
            for line in self.result_list:
                tag = self.get_tag_by_line(line)
                if tag == button:
                    display_result.append(line)
                else:
                    self.update_flag_count(tag)
        elif button == "black_tag":
            for line in self.result_list:
                if "域名提取" in line[1]:
                    domain_list.append(line)
                elif "绝对路径" in line[1]:
                    juedui_path.append(line)
                elif "相对路径" in line[1]:
                    xinagdui_path.append(line)
                else:
                    tag = self.get_tag_by_line(line)
                    self.update_flag_count(tag)
        else:
            display_result = self.result_list

        # 显示结果
        if display_result:
            for line in display_result:
                tag = self.get_tag_by_line(line)
                self.update_flag_count(tag)
                # 这里不添加文件路径，因为很容易找到
                text_line = (line[0] + f"（{line[1]}）").replace('\'', '').replace('\"', '')
                self.output_box.insert(tk.END, text_line + "\n", tag)
        elif is_black_tag:
            self.flag[3] = len(xinagdui_path) + len(juedui_path) + len(domain_list)
            self.output_box.insert(tk.END, "绝对路径：\n", "black_tag")
            for line in juedui_path:
                self.output_box.insert(tk.END, line[0].replace('\'', '').replace('\"', '') + "\n", "black_tag")
            self.output_box.insert(tk.END, "\n")
            self.output_box.insert(tk.END, "相对路径：\n", "black_tag")
            for line in xinagdui_path:
                if line in regex_rules.exclude_content:
                    continue
                self.output_box.insert(tk.END, line[0].replace('\'', '').replace('\"', '') + "\n", "black_tag")
            self.output_box.insert(tk.END, "\n")
            self.output_box.insert(tk.END, "域名提取：\n", "black_tag")    
            for line in domain_list:
                self.output_box.insert(tk.END, line[0].replace('\'', '').replace('\"', '') + "\n", "black_tag")

        else:
            self.output_box.insert(tk.END, "无匹配\n", "gray_tag")
        
        # 更新按钮文本
        for btn in self.button_refs:
            btn.configure(state=tk.NORMAL)
        self.refresh_button_counts(len(self.result_list))
        self.output_box.config(state=tk.DISABLED)

    # 配置默认提示文本
    def set_entry_placeholder(self, entry, placeholder, color="gray"):
        def on_focus_in(event):
            if entry.get() == placeholder:
                entry.delete(0, tk.END)
                entry.config(fg="black")
        def on_focus_out(event):
            if not entry.get():
                entry.insert(0, placeholder)
                entry.config(fg=color)
        entry.insert(0, placeholder)
        entry.config(fg=color)
        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
    
    # 判断 url 是否正确
    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
        
    # 判断 url 是否是 js 链接
    def is_js_url(self, url):
        # 解析URL
        parsed = urlparse(url)
        # 取出路径部分
        path = parsed.path
        # 判断是否以.js结尾
        return path.lower().endswith('.js')

    # 根据行内容确定标签类型
    def get_tag_by_line(self, line):
        """
        根据行内容确定标签类型
        
        Args:
            line: 要分析的行文本
            
        Returns:
            str: 标签类型
        """
        if any(keyword in line[1] for keyword in self.first_keywords):
            return "red_tag"
        elif any(keyword in line[1] for keyword in self.second_keywords):
            return "orange_tag"
        elif any(keyword in line[1] for keyword in self.third_keywords):
            return "green_tag"
        elif any(keyword in line[1] for keyword in self.fourth_keywords):
            return "black_tag"
        else:
            return "gray_tag"
    
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
            self.scan_file_button.config(background="#FFB6C1", foreground="#FF1493")
            self.scan_files_button.config(background="#FFB6C1", foreground="#FF1493")
            self.open_reports_btn.config(background="#FFB6C1", foreground="#FF1493")
                
        elif theme_name == '浅蓝':
            self.output_box.tag_configure("red_tag", foreground="#E74C3C")  # 鲜红色
            self.output_box.tag_configure("orange_tag", foreground="#F39C12")  # 橙黄色
            self.output_box.tag_configure("green_tag", foreground="#27AE60")  # 祖母绿
            self.output_box.tag_configure("gray_tag", foreground="#7F8C8D")  # 青灰色
            self.output_box.tag_configure("black_tag", foreground="black")
            
            # 按钮样式
            for btn in self.button_refs:
                btn.configure(background="#BBE1FF", foreground="#1E6CB0")
            self.scan_file_button.config(background="#BBE1FF", foreground="#1E6CB0")
            self.scan_files_button.config(background="#BBE1FF", foreground="#1E6CB0")
            self.open_reports_btn.config(background="#BBE1FF", foreground="#1E6CB0")
                
        elif theme_name == '浅色':
            self.output_box.tag_configure("red_tag", foreground="#c0392b")  # 暗红色
            self.output_box.tag_configure("orange_tag", foreground="#d35400")  # 砖橙色
            self.output_box.tag_configure("green_tag", foreground="#16a085")  # 深绿色
            self.output_box.tag_configure("gray_tag", foreground="#7f8c8d")  # 深灰色
            self.output_box.tag_configure("black_tag", foreground="black")
            
            # 按钮样式
            for btn in self.button_refs:
                btn.configure(background="#bdc3c7", foreground="#2c3e50")
            self.scan_file_button.config(background="#bdc3c7", foreground="#2c3e50")
            self.scan_files_button.config(background="#bdc3c7", foreground="#2c3e50")
            self.open_reports_btn.config(background="#bdc3c7", foreground="#2c3e50")
        else:  # 默认主题
            self.output_box.tag_configure("red_tag", foreground="red")
            self.output_box.tag_configure("orange_tag", foreground="orange")
            self.output_box.tag_configure("green_tag", foreground="green")
            self.output_box.tag_configure("gray_tag", foreground="gray")
            self.output_box.tag_configure("black_tag", foreground="black")
            
            # 按钮样式
            for btn in self.button_refs:
                btn.configure(background="#e0e0e0", foreground="#333333")
            self.scan_file_button.config(background="#e0e0e0", foreground="#333333")
            self.scan_files_button.config(background="#e0e0e0", foreground="#333333")
            self.open_reports_btn.config(background="#e0e0e0", foreground="#333333")
        # 根据当前结果刷新显示
        self.update_output()

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

    def open_reports_folder(self):
        # 拼接 reports 文件夹路径
        reports_path = os.path.join(self.packer_dir, "reports")
        if not os.path.exists(reports_path):
            # os.makedirs(reports_path)
            messagebox.showerror("错误", "报告夹不存在")
            return
        try:
            os.startfile(reports_path)
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件夹: {e}")

def create_find_path_page(parent, main_app):
    return FindPathPage(parent, main_app)