import tkinter as tk
from tkinter import ttk
import threading
import os
from tkinter import messagebox
import subprocess
import webbrowser

class QuickStart(ttk.Frame):
    """
    小工具类

    快速启动常用渗透工具
    """
    def __init__(self, parent, main_app):
        super().__init__(parent)
        # 保存主应用程序引用
        self.main_app = main_app

        # 获取当前主题
        self.current_theme = main_app.config.get('theme', '默认')
        self.current_directory = main_app.bbdolt_tools_filepath

        # 初始化变量
        self.init_variables()

        # 创建界面
        self.create_widgets()

        # 配置样式
        self.setup_styles()

    def init_variables(self):
        self.row_count = 5
        self.tomcatscanpro_path = self.main_app.config.get('TomcatScanPro', '')
        self.python_path = self.main_app.config.get('python', '')
        self.notepad_path = self.main_app.config.get('notepad', 'notepad')

    def create_widgets(self):
        # 创建主框架
        self.main_frame = ttk.Frame(self, padding="10", style="Border.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 规划网格布局
        for i in range(self.row_count):
            self.main_frame.rowconfigure(i, weight=0)
        self.main_frame.columnconfigure(0, weight=1)

        # 快速启动 TomcatScanPro
        self.tomcat_scan_frame = ttk.LabelFrame(self.main_frame, text=" TomacatScanPro 模块 ", padding="3", style="Border.TFrame")
        self.tomcat_scan_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        # 导入 urls 按钮
        self.tomcat_scan_input=ttk.Button(
            self.tomcat_scan_frame, text="导入 urls", command=self.tomcatscanpro_import_urls, style="ButtonTheme.TButton"
        )
        self.tomcat_scan_input.pack(side='left',padx=5, pady=5,anchor='nw')
        # 开始扫描按钮
        self.tomcat_scan_start = ttk.Button(
            self.tomcat_scan_frame, text="开始漏扫", command=self.tomcatscanpro_start, style="ButtonTheme.TButton"
        )
        self.tomcat_scan_start.pack(side='left',padx=10, pady=5, anchor='nw')
        # 打开扫描结果按钮
        self.tomcat_scan_result = ttk.Button(
            self.tomcat_scan_frame, text="打开扫描结果", command=self.tomcatscanpro_result, style="ButtonTheme.TButton"
        )
        self.tomcat_scan_result.pack(side='left', padx=10, pady=5, anchor='nw')
        # tomcatscanpro 使用教程
        self.tomcat_scan_readme = ttk.Button(
            self.tomcat_scan_frame,
            text="使用手册",
            command=self.open_readme,
            style="ButtonTheme.TButton"
        )
        self.tomcat_scan_readme.pack(side='left', padx=10, pady=5, anchor='nw')


        # AI 接口分析模块
        self.ai_analysis_frame = ttk.LabelFrame(self.main_frame, text=" AI 接口分析模块 ", padding="3", style="Border.TFrame")
        self.ai_analysis_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        # 导入 urls 按钮
        self.ai_analysis_input_button=ttk.Button(
            self.ai_analysis_frame, text="导入 urls", command=self.ai_analysis_import_urls, style="ButtonTheme.TButton"
        )
        self.ai_analysis_input_button.pack(side='left',padx=5, pady=5,anchor='nw')
        # 开始分析按钮
        self.ai_analysis_start_button = ttk.Button(
            self.ai_analysis_frame, text="开始分析", command=self.ai_analysis_start, style="ButtonTheme.TButton"
        )
        self.ai_analysis_start_button.pack(side='left',padx=10, pady=5, anchor='nw')
        # 打开扫描结果
        self.ai_analysis_result_button = ttk.Button(
            self.ai_analysis_frame, text="打开扫描结果", command=self.ai_analysis_result, style="ButtonTheme.TButton"
        )
        self.ai_analysis_result_button.pack(side='left', padx=10, pady=5, anchor='nw')
        # ai 接口分析使用手册
        self.ai_analysis_readme_button = ttk.Button(
            self.ai_analysis_frame,
            text="使用手册",
            command=self.open_readme,
            style="ButtonTheme.TButton"
        )
        self.ai_analysis_readme_button.pack(side='left', padx=10, pady=5, anchor='nw')


    def setup_styles(self):
        self.apply_theme(self.current_theme)

    def apply_theme(self, theme_name):
        # 创建 ttk.Style 对象
        self.style = ttk.Style()

        # 定义 ButtonTheme 样式
        self.style.configure('ButtonTheme.TButton', 
                             background='#2c3e50',  # 背景颜色
                             foreground='#ecf0f1',  # 前景颜色
                             font=('Helvetica', 12, 'bold'),  # 字体
                             bordercolor='#2c3e50',  # 边框颜色
                             lightcolor='#2c3e50',  # 按钮按下时的亮色
                             darkcolor='#2c3e50')   # 按钮按下时的暗色

    # 输入需要扫描的 url
    def tomcatscanpro_import_urls(self):
        file_path = os.path.abspath(os.path.join(self.tomcatscanpro_path,'data/urls.txt'))
        cmd = f'"{self.notepad_path}" "{file_path}"'
        if os.path.exists(file_path):
            try:
                subprocess.Popen(cmd)
            except Exception as e:
                messagebox.showerror("启动失败", f"启动进程时出错：{e}")
        else:
            messagebox.showerror("文件不存在", f"文件 {file_path} 不存在，请检查路径是否正确。")

    # 开始扫描
    def tomcatscanpro_start(self):
        file_path = os.path.abspath(os.path.join(self.tomcatscanpro_path, 'TomcatScanPro.py'))
        python_path = os.path.abspath(self.python_path)
        if os.path.exists(file_path):
            print("开始扫描")
            # cmd = f'"{python_path}" "{file_path}"'
            cmd = f'start "" cmd /k "{python_path} {file_path}"'
            print(f"执行命令: {cmd}")
            try:
                # subprocess.Popen(cmd, cwd=self.tomcatscanpro_path, creationflags=subprocess.CREATE_NEW_CONSOLE)
                subprocess.Popen(cmd, cwd=self.tomcatscanpro_path, shell=True)
            except Exception as e:
                messagebox.showerror("启动失败", f"启动进程时出错：{e}")
        else:
            messagebox.showerror("文件不存在", f"文件 {file_path} 不存在，请检查路径是否正确。")

    # 打开扫描结果
    def tomcatscanpro_result(self):
        file_path = os.path.abspath(os.path.join(self.tomcatscanpro_path,'success.txt'))
        if self.notepad_path=="notepad++":
            cmd = [self.notepad_path, "-ro", file_path]
        else:
            cmd = [self.notepad_path, file_path]
        print(cmd)
        if os.path.exists(file_path):
            try:
                subprocess.Popen(cmd)
            except Exception as e:
                messagebox.showerror("启动失败", f"启动进程时出错：{e}")
        else:
            messagebox.showerror("文件不存在", f"文件 {file_path} 不存在，请检查路径是否正确。")

    # 打开 tomcatscanpro 使用手册
    def open_readme(self):
        """
        用默认浏览器打开当前目录下的 README.html 文件
        
        参数:
            无
        
        返回:
            无
        """
        # 构建完整的文件路径
        readme_path = os.path.join(self.current_directory, "Tools/README.html")
        
        # 检查文件是否存在
        if not os.path.exists(readme_path):
            print(f"错误: 找不到 {readme_path} 文件")
            return
        
        try:
            # 使用默认浏览器打开文件
            webbrowser.open('file://' + os.path.abspath(readme_path))
        except Exception as e:
            print(f"打开文件时出错: {e}")

    # AI 接口分析需要先写入 url
    def ai_analysis_import_urls(self):
        file_path = os.path.join(self.current_directory, 'Tools/Interface_analysis/urls.txt')
        cmd = f'"{self.notepad_path}" "{file_path}"'
        if os.path.exists(file_path):
            try:
                subprocess.Popen(cmd)
            except Exception as e:
                messagebox.showerror("启动失败", f"启动进程时出错：{e}")
    
    # 开始分析
    def ai_analysis_start(self):
        file_path = os.path.join(self.current_directory, 'Tools/Interface_analysis/interface_analysis.py')
        file_dir = os.path.dirname(file_path)
        url_path = os.path.join(self.current_directory, 'Tools/Interface_analysis/urls.txt')
        python_path = os.path.abspath(self.python_path)
        if os.path.exists(file_path):
            print("开始分析")
            cmd = f'start "" cmd /k "{python_path} {file_path} -r {url_path} -o results_active.txt"'
            try:
                subprocess.Popen(cmd, cwd=file_dir, shell=True)
            except Exception as e:
                messagebox.showerror("启动失败", f"启动进程时出错：{e}")
        else:
            messagebox.showerror("文件不存在", f"文件 {file_path} 不存在，请检查路径是否正确。")

    # 打开分析结果
    def ai_analysis_result(self):
        file_path = os.path.join(self.current_directory, 'Tools/Interface_analysis/data/results_active.txt')
        if self.notepad_path=="notepad++":
            cmd = [self.notepad_path, "-ro", file_path]
        else:
            cmd = [self.notepad_path, file_path]
        print(cmd)
        if os.path.exists(file_path):
            try:
                subprocess.Popen(cmd)
            except Exception as e:
                messagebox.showerror("启动失败", f"启动进程时出错：{e}")
        else:
            messagebox.showerror("文件不存在", f"文件 {file_path} 不存在，请检查路径是否正确。")

    # def ai_analysis_readme(self):
    #     pass

# 创建匹配检测也页面的实例
def create_quick_start_page(parent, main_app):
    return QuickStart(parent, main_app)