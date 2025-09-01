import tkinter as tk
from tkinter import ttk
import threading

class AboutPage(ttk.Frame):
    """
    关于页面类
    
    提供关于信息展示和联系方式。
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

    # 初始化变量
    def init_variables(self):
        # LOGO 文字
        self.logo_text = r"""
   ____   ____  _         _       _ _          _ _   _           _      _
  / __ \ | __ )| |__   __| | ___ | | |_   __ _(_| |_| |__  _   _| |__  (_) ___ 
 / / _` ||  _ \| '_ \ / _` |/ _ \| | __| / _` | | __| '_ \| | | | '_ \ | |/ _ \ 
| | (_| || |_) | |_) | (_| | (_) | | |_ | (_| | | |_| | | | |_| | |_) _| | (_) |
 \ \__,_||____/|_.__/ \__,_|\___/|_|\__(_\__, |_|\__|_| |_|\__,_|_.__(_|_|\___/
  \____/                                 |___/"""
        # LOGO 图标
        self.logo_art = r"""
              *         *      *         *
          ***          **********          ***
       *****           **********           *****
     *******           **********           *******
   **********         ************         **********
  ****************************************************
 ******************************************************
********************************************************
********************************************************
********************************************************
 ******************************************************
  ********      ************************      ********
   *******       *     *********      *       *******
     ******             *******              ******
       *****             *****              *****
          ***             ***              ***
            **             *              **
"""
        # 版本信息
        self.version_info = """
Bbdolt_Tools v1.0
        
Copyright © 2024 Bbdolt安全
保留所有权利
        
基于Python和Tkinter开发的安全工具箱
"""

    # 创建界面
    def create_widgets(self):
        # 创建主框架
        self.main_frame = ttk.Frame(self, padding="10", style="Border.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建上部容器和下部容器
        top_container = ttk.Frame(self.main_frame)
        top_container.pack(fill=tk.X, side=tk.TOP, pady=5)
        
        bottom_container = ttk.Frame(self.main_frame)
        bottom_container.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM, pady=5)

        # 左上方 - logo文本区域
        self.logo_text_frame = ttk.Frame(top_container, padding="10")
        self.logo_text_frame.pack(side=tk.LEFT, anchor="nw")

        # 添加 logo 文本 - 使用等宽字体，禁用文本换行
        self.logo_text_label = tk.Label(
            self.logo_text_frame,
            text=self.logo_text,
            font=("Courier New", 10),  # 确保使用等宽字体
            justify=tk.LEFT,
            wraplength=0,  # 禁用自动换行
            padx=5,
            pady=5
        )
        self.logo_text_label.pack(anchor="nw")

        # 右上方 - 版本介绍
        self.version_text_frame = ttk.Frame(top_container, padding="10")
        self.version_text_frame.pack(side=tk.RIGHT, anchor="ne")

        # 添加介绍版本信息
        self.version_text_label = tk.Label(
            self.version_text_frame,
            text=self.version_info,
            font=("Courier New", 10),
            justify=tk.LEFT,
            wraplength=0,
            padx=5,
            pady=5
        )
        self.version_text_label.pack(anchor="nw")

        # 右下方 - logo图像区域 
        self.logo_art_frame = ttk.Frame(bottom_container, padding="10")
        self.logo_art_frame.pack(side=tk.RIGHT, anchor="se")

        # 添加logo图像 - 使用等宽字体，禁用文本换行
        self.logo_art_label = tk.Label(
            self.logo_art_frame,
            text=self.logo_art,
            font=("Courier New", 9),  # 尝试略小的字体
            justify=tk.LEFT,  # 改为左对齐确保每行开始位置一致
            wraplength=0,  # 禁用自动换行
            padx=10,
            pady=10
        )
        self.logo_art_label.pack(anchor="center")

        # 友情链接
        self.link_frame = ttk.Frame(bottom_container, padding="10")
        self.link_frame.pack(side=tk.LEFT, anchor="sw")

        # 添加友情链接
        links = [
            ("博客网站", "https://bbdolt.github.io"),
            ("Github", "https://github.com/Bbdolt"),
            ("B站链接", "https://space.bilibili.com/1698476122"),
            ("微信公众号", "https://mp.weixin.qq.com/s/jEbOeeCfW4aqbNB1jlPE2w"),
            ("CSDN链接", "https://blog.csdn.net/m0_73779708?type=blog"),
            ("支持作者", "https://bbdolt.github.io/img/Wechat.jpg")  # 特殊标记，不是URL
        ]
        for i, (name, url) in enumerate(links):
            link_button = ttk.Button(
                self.link_frame,
                text=f"{name}",
                command=lambda u=url: self.open_url(u)
            )
            link_button.grid(row=i, column=0, padx=5, pady=5, sticky="w")

    # 定义样式
    def setup_styles(self):
        # 应用当前主题
        self.apply_theme(self.current_theme)

    def apply_theme(self, theme_name):
        """应用主题"""
        if theme_name == '粉色':
            self.logo_text_label.config(fg="#FF1493", bg="#FFF0F5")
            self.logo_art_label.config(fg="#FF1493", bg="#FFF0F5")
            self.version_text_label.config(fg="#FF1493", bg="#FFF0F5")
            # self.info_label.config(fg="#FF1493", bg="#FFF0F5")
        elif theme_name == '浅蓝':
            self.logo_text_label.config(fg="#1E6CB0", bg="#E6F3FF")
            self.logo_art_label.config(fg="#1E6CB0", bg="#E6F3FF")
            self.version_text_label.config(fg="#1E6CB0", bg="#E6F3FF")
            # self.info_label.config(fg="#1E6CB0", bg="#E6F3FF")
        elif theme_name == '浅色':
            self.logo_text_label.config(fg="#2c3e50", bg="#ecf0f1")
            self.logo_art_label.config(fg="#2c3e50", bg="#ecf0f1")
            self.version_text_label.config(fg="#2c3e50", bg="#ecf0f1")
            # self.info_label.config(fg="#2c3e50", bg="#ecf0f1")
        else:  # 默认主题
            self.logo_text_label.config(fg="#333333", bg="#f0f0f0")
            self.logo_art_label.config(fg="#333333", bg="#f0f0f0")
            self.version_text_label.config(fg="#333333", bg="#f0f0f0")
            # self.info_label.config(fg="#333333", bg="#f0f0f0")

    # 处理按钮事件
    def open_url(self, url):
        """
        在单独线程中打开URL链接，避免UI阻塞
        
        Args:
            url: 要打开的URL
        """
        # 创建新线程来处理URL打开
        threading.Thread(
            target=self._open_url_thread,
            args=(url,),
            daemon=True  # 设为守护线程，这样主程序退出时线程会自动终止
        ).start()

    def _open_url_thread(self, url):
        """
        在单独线程中执行的URL打开函数
        
        Args:
            url: 要打开的URL
        """
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception as e:
            # 使用after方法在主线程中显示错误消息
            self.after(0, lambda: self._show_error(f"无法打开链接: {str(e)}"))

    def _show_error(self, message):
        """
        显示错误消息
        
        Args:
            message: 错误信息
        """
        from tkinter import messagebox
        messagebox.showerror("链接错误", message)
    
# 创建匹配检测页面的实例
def create_about_page(parent, main_app):
    return AboutPage(parent, main_app)
        
        

