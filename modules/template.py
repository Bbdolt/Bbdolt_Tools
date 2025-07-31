import tkinter as tk
from tkinter import ttk

class Template(ttk.Frame):
    """
    模板类

    提供模板方便使用者更专注于功能实现。
    """
    def __init__(self, parent, main_app):
        super().__init__(parent)
        # 保存主应用程序引用
        self.main_app = main_app

        # 获取当前主题
        self.current_theme = main_app.config.get('theme', '默认')

        # 初始化变量
        self.init_variables()

        # 创建界面
        self.create_widgets()

        # 配置样式
        self.setup_styles()

    def init_variables(self):
        pass

    def create_widgets(self):
        # 创建主框架
        self.main_frame = ttk.Frame(self, padding="10", style="Border.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
    
    def setup_styles(self):
        self.apply_theme(self.current_theme)
    
    def apply_theme(self, theme_name):
        pass

# 创建匹配检测也页面的实例
def create_template_page(parent, main_app):
    return Template(parent, main_app)