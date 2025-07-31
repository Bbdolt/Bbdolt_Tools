# Bbdolt_Tools 开发文档

## 模块开发指南

### 基本要求

1. 所有模块必须继承 `ttk.Frame`
2. 必须实现标准的初始化接口
3. 必须提供模块创建函数

### 模块结构

每个模块应遵循以下标准结构（可参考 Template.py）：

```python
import tkinter as tk
from tkinter import ttk

class YourModule(ttk.Frame):
    """
    您的模块类
    
    为您的模块提供详细的文档字符串，说明其功能和用途。
    """
    def __init__(self, parent, main_app):
        """
        初始化模块
        
        Args:
            parent: 父级窗口组件
            main_app: 主应用程序实例，提供配置访问、资源管理等功能
        """
        super().__init__(parent)
        self.main_app = main_app
        
        # 初始化变量
        self.init_variables()
        
        # 创建界面
        self.create_widgets()
        
        # 配置样式
        self.setup_styles()
    
    def init_variables(self):
        """初始化变量"""
        # 在这里初始化所有模块需要的变量
        pass
    
    def create_widgets(self):
        """创建界面组件"""
        # 在这里创建和布局所有UI组件
        pass
    
    def setup_styles(self):
        """配置界面样式"""
        # 在这里配置组件样式，可以使用ttk.Style
        pass

# 模块创建函数 - 必须按照此格式实现
def create_module_frame(parent, main_app):
    """
    创建模块实例
    
    Args:
        parent: 父级窗口组件
        main_app: 主应用程序实例
        
    Returns:
        YourModule: 模块实例
    """
    return YourModule(parent, main_app)
```

### 标准接口实现指南

#### 初始化函数

初始化函数必须接收两个参数：`parent` 和 `main_app`。

- `parent`：父级窗口组件，用于放置模块UI
- `main_app`：主应用程序实例，提供配置访问、资源管理等功能

建议在初始化函数中调用以下三个方法：

1. `init_variables()`：初始化所有模块变量
2. `create_widgets()`：创建和配置UI组件
3. `setup_styles()`：设置UI样式

#### 创建模块框架函数

每个模块必须提供一个名为 `create_module_frame` 的函数，该函数接收 `parent` 和 `main_app` 参数，并返回模块实例。主程序将通过此函数创建和加载模块。

### 资源管理

使用主程序提供的资源管理机制，确保在模块不再使用时正确释放资源：

```python
# 注册资源
self.main_app.register_resource("resource_id", cleanup_function)

# 取消注册
self.main_app.unregister_resource("resource_id")
```

资源清理函数应该负责释放模块创建的所有资源，如线程、连接等：

```python
def cleanup_function(self):
    """清理资源函数"""
    # 停止所有线程
    self.running = False
    
    # 关闭所有连接
    if hasattr(self, 'connection') and self.connection:
        self.connection.close()
    
    # 释放其他资源
    # ...
```

### 多线程处理

对于可能阻塞UI的长时间操作，应使用线程处理：1

```python
def start_long_operation(self):
    """启动长时间操作"""
    # 创建并启动工作线程
    self.worker_thread = threading.Thread(target=self.work_function, daemon=True)
    self.worker_thread.start()

def work_function(self):
    """工作线程函数"""
    try:
        # 执行长时间操作
        pass
    except Exception as e:
        # 错误处理
        print(f"操作出错: {str(e)}")
    finally:
        # 确保资源被清理
        self.cleanup_resources()
```

### 主题系统

每个模块应实现 `apply_theme` 方法以支持主题切换：

```python
def apply_theme(self, theme_name):
    """
    应用指定的主题样式
    
    Args:
        theme_name: 主题名称
    """
    # 根据主题名称应用相应样式
    if theme_name == '粉色':
        # 应用粉色主题样式
        pass
    elif theme_name == '浅蓝':
        # 应用浅蓝主题样式
        pass
    # ... 其他主题
```

### 模块注册

开发完成后，需要在主程序中注册您的模块。将以下代码添加到main.py的适当位置：

```python
# 导入模块
from modules.your_module import create_module_frame as create_your_module

# 在模块列表中注册
menu_groups = {
    "安全工具": [
        ("敏感信息提取", matches.create_matches_frame),
        ("提取接口信息", find_path.create_find_path_frame)
    ],
    "主界面": [
        ("关于作者", about.create_about_frame),
    ]
}
```

## 主题系统

### 可用的主题

1. 默认主题
2. 粉色主题
3. 浅蓝主题
4. 浅色主题

### 主题颜色参考

```python
themes = {
    "默认": {
        "background": "#f0f0f0",
        "foreground": "#333333"
    },
    "粉色": {
        "background": "#FFF0F5",
        "foreground": "#FF69B4"
    },
    "浅蓝": {
        "background": "#E6F3FF",
        "foreground": "#2C88D9"
    },
    "浅色": {
        "background": "#ecf0f1",
        "foreground": "#2c3e50"
    }
}
```

## 配置系统

### 配置文件结构 config.json

```json
{
    "theme": "浅蓝",
    "http_port": 9015,
    "packerfuzzer": ""
}
```

### 读取配置

```python
setting_value = self.main_app.config.get("your_setting", "default_value")
```

### 保存配置

配置会在程序关闭时自动保存。如需立即保存特定设置：

```python
self.main_app.config.set("your_setting", "new_value")
self.main_app.save_theme_setting()  # 可选，如果需要立即保存
```