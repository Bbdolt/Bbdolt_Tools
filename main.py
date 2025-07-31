import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from modules import matches, about, find_path, quick_start

class MainApplication:
    """
    主应用程序类，负责创建和管理整个应用程序的界面和功能。
    
    属性:
        root: tkinter主窗口实例
        main_frame: 主框架，包含所有界面元素
        config: 应用程序配置字典
        pages: 存储所有页面的字典
        menu_buttons: 存储所有菜单按钮的字典
        current_page: 当前显示的页面名称
    """
    # 初始化应用程序
    def __init__(self, root):
        """
        初始化应用程序实例。
        
        参数:
            root: tkinter主窗口实例
        """
        self.bbdolt_tools_filepath = os.path.dirname(os.path.abspath(__file__))
        self.icon_path = os.path.join(self.bbdolt_tools_filepath, 'ico/icon32_32x32.ico')
        self.config_path = os.path.join(self.bbdolt_tools_filepath, 'config.json')
        # self.icon_path = "ico/icon32_32x32.ico"
        # self.config_path = "config.json"
        self.root = root
        self.root.title("Bbdolt_Tools v1.0")
        self.root.geometry("1280x800")
        self.root.minsize(1024, 768)
        try:
            self.root.iconbitmap(self.icon_path)
        except Exception:
            print("图标位置不存在")
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        # 用于跟踪活跃的资源和进程
        self.active_resources = {}
        # 加载配置
        self.load_config()
        
        # 创建样式
        self.setup_styles()
        
        # 创建布局
        self.create_layout()

        # 添加正常的窗口关闭处理
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # 注册需要清理的资源，如线程或连接
    def register_resource(self, resource_id, cleanup_func):
        """
        注册需要清理的资源
        
        参数:
            resource_id: 资源的唯一标识符
            cleanup_func: 清理该资源的函数
        """
        self.active_resources[resource_id] = cleanup_func

    # 取消注册资源，通常用于资源已被释放后调用
    def unregister_resource(self, resource_id):
        """
        取消注册资源
        """
        if resource_id in self.active_resources:
            del self.active_resources[resource_id]

    # 清理所用注册的资源，通常在程序关闭时调用
    def cleanup_resources(self):
        """
        清理所有注册的资源
        """
        cleanup_errors = []
        for resource_id, cleanup_func in self.active_resources.items():
            try:
                cleanup_func()
            except Exception as e:
                cleanup_errors.append(f"清理资源 {resource_id} 时出错: {str(e)}")
        
        if cleanup_errors:
            error_message = "\n".join(cleanup_errors)
            messagebox.showerror("资源清理错误", 
                f"在清理资源时发生以下错误：\n{error_message}")
        
        self.active_resources.clear()

    # 处理窗口关闭事件，确保资源被清理并保存配置
    def on_closing(self):
        """
        处理窗口关闭事件，确保所有资源都被正确清理
        """
        if len(self.active_resources) > 0:
            if not messagebox.askokcancel("退出确认", 
                "有正在运行的任务，确定要退出吗？\n这可能会导致正在进行的操作被中断。"):
                return
        
        try:
            # 清理所有注册的资源
            self.cleanup_resources()
            
            # 保存配置
            try:
                with open('config.json', 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, ensure_ascii=False, indent=4)
            except Exception as e:
                messagebox.showerror("错误", f"保存配置文件失败: {str(e)}")
            
            # 销毁主窗口
            self.root.destroy()
            
        except Exception as e:
            messagebox.showerror("错误", f"程序退出时发生错误: {str(e)}")
            # 如果出现严重错误，强制退出
            self.root.destroy()
    
    # 设置应用程序的视觉样式，配置全局主题
    def setup_styles(self):
        """
        设置应用程序的视觉样式。
        配置全局主题、按钮样式、工具栏样式等界面元素的外观。
        如果配置文件中存在主题设置，会应用保存的主题。
        """
        style = ttk.Style()
        style.theme_use('clam')

        # 设置左侧菜单栏格式
        style.configure("TLabelframe", background="#e0e0e0")
        style.configure("TLabelframe.Label", font=("Arial", 10, "bold"))

        # 添加边框样式
        style.configure("Border.TFrame", 
                        borderwidth=2,         # 增加边框宽度，使其更明显
                        relief="groove")
                
        # 主题颜色
        style.configure('.',
            background='#f0f0f0',
            foreground='#333333',
            font=('Microsoft YaHei UI', 10)
        )
        
        # 侧边栏按钮样式
        style.configure('Sidebar.TButton',
            padding=10,
            width=16,
            font=('Microsoft YaHei UI', 11)
        )
        
        # 选中状态的侧边栏按钮
        style.configure('Sidebar.Selected.TButton',
            background='#2c3e50',
            foreground='white'
        )
        
        # 工具栏样式
        style.configure('Toolbar.TFrame',
            background='#34495e'
        )
        
        # 设置框架样式
        style.configure('Settings.TLabelframe',
            background='#f0f0f0',
            foreground='#333333'
        )
        
        # 如果配置中有主题设置，应用它
        if 'theme' in self.config:
            self.apply_theme(self.config['theme'])
    
    # 创建应用主布局，包括工具栏、主容器（侧边栏和主内容区域）
    def create_layout(self):
        """
        创建应用程序的主要布局。
        包括工具栏、侧边栏和主内容区域的创建和排列。
        """
        # 创建顶部工具栏
        self.create_toolbar()
        
        # 创建主容器（下面有左侧菜单，和主内容区域）
        self.content_container = ttk.Frame(self.main_frame)
        self.content_container.pack(fill=tk.BOTH, expand=True)

        # 配置网格格局
        self.content_container.columnconfigure(0, weight=0)  # 侧边栏列不伸缩
        self.content_container.columnconfigure(1, weight=1)  # 主内容区域占据所有剩余空间
        self.content_container.rowconfigure(0, weight=1)     # 行可以伸缩
        
        # 创建左侧菜单
        self.create_sidebar()
        
        # 创建主内容区域
        self.create_main_content()
    
    # 创建顶部工具栏
    def create_toolbar(self):
        """
        创建顶部工具栏。
        包含设置按钮和帮助按钮。
        """
        toolbar = ttk.Frame(self.main_frame, style='Toolbar.TFrame', height=40)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        
        # 添加工具栏按钮
        ttk.Button(toolbar, text="设置", width=8, command=self.show_settings).pack(side=tk.RIGHT, padx=5, pady=5)
        # ttk.Button(toolbar, text="帮助", width=8, command=self.show_help).pack(side=tk.RIGHT, padx=5, pady=5)

    # 左侧菜单栏（在这里定义功能）
    def create_sidebar(self):
        """
        创建左侧菜单栏。
        包含所有功能模块的导航按钮，但不显示设置按钮。
        使用分组框架区分不同类型的模块。
        """
        # 侧边栏容器
        self.sidebar = ttk.Frame(self.content_container, width=200, style="Border.TFrame")
        self.sidebar.grid(row=0, column=0, sticky="ns", padx=(5, 2), pady=5)
        self.sidebar.grid_propagate(False)
        # 定义菜单分组
        menu_groups = {
            "主界面": [
                ("关于作者", about.create_about_page),
            ],
            "安全工具": [
                ("敏感信息提取", matches.create_matches_page),
                ("提取接口信息", find_path.create_find_path_page),
                ("工具箱", quick_start.create_quick_start_page)
            ]
        }
        
        # 收集所有菜单项
        self.menu_items = []
        for group_items in menu_groups.values():
            self.menu_items.extend(group_items)
        
        # 添加设置页面到页面列表（但不在侧边栏显示）
        self.all_pages = self.menu_items + [("设置", self.create_settings_page)]
        
        # 创建分组框架和菜单按钮
        self.menu_buttons = {}
        for group_name, group_items in menu_groups.items():
            # 创建带标签的分组框架
            group_frame = ttk.LabelFrame(self.sidebar, text=group_name)
            group_frame.pack(fill=tk.X, padx=5, pady=5)
            
            # 在分组内创建按钮
            for text, _ in group_items:
                btn = ttk.Button(
                    group_frame,
                    text=text,
                    style='Sidebar.TButton',
                    command=lambda t=text: self.switch_page(t)
                )
                btn.pack(fill=tk.X, padx=2, pady=1)
                self.menu_buttons[text] = btn

    # 主要内容区域（所有功能页面显示的地方）   
    def create_main_content(self):
        """
        创建主内容区域。
        初始化所有功能页面，并显示默认页面。
        """
        # 主内容区域 - 使用grid而不是pack
        self.main_content = ttk.Frame(self.content_container)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=(2, 5), pady=5)
        
        
        # 创建所有页面
        self.pages = {}
        for text, create_func in self.all_pages:
            page = create_func(self.main_content, self)
            self.pages[text] = page
            
        # 默认显示第一个页面
        self.current_page = self.menu_items[0][0]
        self.pages[self.current_page].pack(fill=tk.BOTH, expand=True)
    
    # 切换显示页面（切换功能点）
    def switch_page(self, page_name):
        """
        切换显示页面。
        
        参数:
            page_name: 要显示的页面名称
        """
        # 隐藏当前页面
        self.pages[self.current_page].pack_forget()
        
        # 显示新页面
        self.pages[page_name].pack(fill=tk.BOTH, expand=True)
        self.current_page = page_name
        
        # 更新按钮样式（只更新可见的菜单按钮）
        if page_name in self.menu_buttons:
            # 先重置所有按钮样式
            for btn in self.menu_buttons.values():
                btn.configure(style='Sidebar.TButton')
            # 设置当前选中按钮的样式
            self.menu_buttons[page_name].configure(style='Sidebar.Selected.TButton')
    
    # 空白页（正在开发...）
    def create_empty_page(self, parent, main_app):
        """
        创建空白页面，用于尚未实现的功能。
        
        参数:
            parent: 父级窗口组件
            main_app: 主应用程序实例
                
        返回:
            ttk.Frame: 包含"功能开发中"提示的框架
        """
        frame = ttk.Frame(parent)
        ttk.Label(frame, text="功能开发中...", font=('Microsoft YaHei UI', 14)).pack(
            expand=True, anchor='center'
        )
        return frame
    
    # 设置页面配置
    def create_settings_page(self, parent, main_app):
        """
        创建设置页面。
        包含主题选择等设置项。
        
        参数:
            parent: 父级窗口组件
            main_app: 主应用程序实例
                
        返回:
            ttk.Frame: 设置页面框架
        """
        frame = ttk.Frame(parent, style="Border.TFrame")
        ttk.Label(frame, text="设置", font=('Microsoft YaHei UI', 14, 'bold')).pack(
            pady=20, anchor='w'
        )
        
        # 添加设置选项
        settings_frame = ttk.LabelFrame(frame, text="常规设置", style='Settings.TLabelframe')
        settings_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # 主题设置
        theme_frame = ttk.Frame(settings_frame)
        theme_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(theme_frame, text="主题:").pack(side=tk.LEFT)
        
        # 创建主题下拉框并设置当前值
        theme_combo = ttk.Combobox(theme_frame, values=['默认', '粉色', '浅蓝', '浅色'], state='readonly')
        theme_combo.bind('<<ComboboxSelected>>', self.on_theme_change)
        current_theme = self.config.get('theme', '默认')
        theme_combo.set(current_theme)
        theme_combo.pack(side=tk.LEFT, padx=5)
        
        return frame
    
    # 主题切换，保存配置
    def on_theme_change(self, event):
        """
        处理主题切换事件。
        
        参数:
            event: 事件对象，包含选中的主题信息
        """
        selected_theme = event.widget.get()
        self.apply_theme(selected_theme)
        self.save_theme_setting(selected_theme)

    # 切换主题
    def apply_theme(self, theme_name):
        """
        应用指定的主题样式。
        
        参数:
            theme_name: 主题名称（'默认'、'粉色'、'浅蓝' 或 '浅色'）
        """
        style = ttk.Style()
        
        if theme_name == '粉色':
            # 粉色主题
            style.configure('.',
                background='#FFF0F5',  # 浅粉色背景
                foreground='#FF69B4'   # 热粉色文字
            )
            style.configure('Sidebar.TButton',
                background='#FFB6C1',  # 浅粉红色按钮背景
                foreground='#FF1493'   # 深粉色按钮文字
            )
            style.configure('Toolbar.TFrame',
                background='#FF69B4'   # 粉色工具栏
            )
            style.configure('Settings.TLabelframe',
                background='#FFF0F5',  # 浅粉色设置框背景
                foreground='#FF69B4'   # 粉色设置框文字
            )
            style.configure('Settings.TLabelframe.Label',
                background='#FFF0F5',  # 浅粉色标签背景
                foreground='#FF69B4'   # 粉色标签文字
            )
            # 选中按钮的样式
            style.configure('Sidebar.Selected.TButton',
                background='#FF69B4',  # 粉色选中背景
                foreground='#FFFFFF'   # 白色文字
            )

        elif theme_name == '浅蓝':
            # 浅蓝色主题
            style.configure('.',
                background='#E6F3FF',  # 浅蓝色背景
                foreground='#2C88D9'   # 蓝色文字
            )
            style.configure('Sidebar.TButton',
                background='#BBE1FF',  # 浅蓝色按钮背景
                foreground='#1E6CB0'   # 深蓝色按钮文字
            )
            style.configure('Toolbar.TFrame',
                background='#7CB9E8'   # 天蓝色工具栏
            )
            style.configure('Settings.TLabelframe',
                background='#E6F3FF',  # 浅蓝色设置框背景
                foreground='#2C88D9'   # 蓝色设置框文字
            )
            style.configure('Settings.TLabelframe.Label',
                background='#E6F3FF',  # 浅蓝色标签背景
                foreground='#2C88D9'   # 蓝色标签文字
            )
            # 选中按钮的样式
            style.configure('Sidebar.Selected.TButton',
                background='#4B9CD3',  # 蓝色选中背景
                foreground='#FFFFFF'   # 白色文字
            )
            
        elif theme_name == '浅色':
            # 浅色主题
            style.configure('.',
                background='#ecf0f1',
                foreground='#2c3e50'
            )
            style.configure('Sidebar.TButton',
                background='#bdc3c7',
                foreground='#2c3e50'
            )
            style.configure('Toolbar.TFrame',
                background='#bdc3c7'
            )
            style.configure('Settings.TLabelframe',
                background='#ecf0f1',
                foreground='#2c3e50'
            )
            style.configure('Settings.TLabelframe.Label',
                background='#ecf0f1',
                foreground='#2c3e50'
            )
            
        else:  # 默认主题
            style.configure('.',
                background='#f0f0f0',
                foreground='#333333'
            )
            style.configure('Sidebar.TButton',
                background='#e0e0e0',
                foreground='#333333'
            )
            style.configure('Toolbar.TFrame',
                background='#34495e'
            )
            style.configure('Settings.TLabelframe',
                background='#f0f0f0',
                foreground='#333333'
            )
            style.configure('Settings.TLabelframe.Label',
                background='#f0f0f0',
                foreground='#333333'
            )
            
        # 更新选中按钮的样式
        style.configure('Sidebar.Selected.TButton',
            background='#2c3e50',
            foreground='white'
        )

        # 只有在页面初始化完成后才尝试更新主题
        if hasattr(self, 'pages'):
            for page_name, page in self.pages.items():
                if hasattr(page, 'apply_theme'):
                    try:
                        page.apply_theme(theme_name)
                    except Exception as e:
                        print(f"更新页面 {page_name} 主题时出错: {str(e)}")

    # 保存配置
    def save_theme_setting(self, theme_name):
        """
        保存主题设置到配置文件。
        
        参数:
            theme_name: 要保存的主题名称
        """
        self.config['theme'] = theme_name
        try:
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            messagebox.showerror("错误", f"保存配置文件失败: {str(e)}")
    
    # 显示设置页面
    def show_settings(self):
        """
        显示设置页面。
        """
        self.switch_page("设置")
    
    # 显示帮助
    def show_help(self):
        """
        显示帮助信息对话框。
        包含工具集的版本信息和功能列表。
        """
        messagebox.showinfo("帮助", 
            "安全工具集 v1.0\n\n"
            "这是一个集成了多种安全测试工具的工具集。\n"
            "包含以下功能：\n"
            "- 信息收集\n"
            "- 端口扫描\n"
            "- 编码转换\n"
            "- Web工具\n"
            "- 系统工具\n"
            "- 加解密\n\n"
            "作者：Bbdolt"
        )

    # 读取配置信息 
    def load_config(self):
        """
        从配置文件加载应用程序设置。
        如果配置文件不存在或加载失败，将使用空配置。
        """
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            else:
                self.config = {}
        except Exception as e:
            messagebox.showerror("错误", f"加载配置文件失败: {str(e)}")
            self.config = {}

def main():
    """
    应用程序入口函数。
    创建主窗口和应用程序实例，启动主事件循环。
    """
    try:
        root = tk.Tk()  # 创建主窗口
        app = MainApplication(root)  # 创建应用程序实例
        root.mainloop()  # 启动事件循环
    except KeyboardInterrupt:
        print("\n程序已安全退出")
    except Exception as e:
        print(f"发生错误: {str(e)}")
    finally:
        try:
            root.destroy()
        except:
            pass

if __name__ == "__main__":
    main()