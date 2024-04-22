"""
方案2: 采用后端工具描述文件，后续读取该文件，尤其是其中的依赖项，
        并使用 magic_eyes_cli check 进行运行环境检查
描述:
        1. 工具名，所属子系统
        2. 工具的简要描述
        3. 是否具有运行依赖项，依赖项是什么？
        
"""

class CpuWatcher():
    def __init__(self):
        self.tool_name = "cpu_watcher"
        self.belong_to_subsystem = "process"
        self.description = "A tool for analyzing CPU running status"
        self.dependencies = {
            """ 工具运行的依赖项 """
        }
        
