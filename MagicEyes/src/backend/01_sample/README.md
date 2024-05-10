### 1. 文件夹含义
- 3rdparty: 工具用到的第三方库，记得导入git的submodule
- bpf: 存放 *.bpf.c代码，用于生成 *.skel.h
- collector: 与bridge交互的代码（为前端可视化）
- include： 头文件
- src： 实现文件
- etc：配置文件
- scripts：项目的一些脚本文件
- tests：测试代码存放目录
- docs：项目实现文档、有用的资料等
### 2. README
1. 项目简介
2. 功能介绍
3. 依赖、编译安装方法
4. 代码结构
5. 使用方法
6. 测试

### 3. CMakeLists.txt
```bash
# 修改工具名
set(TOOL_NAME cpu_watcher)
# 修改项目所属子系统
set(TOOL_BELONG_TO_MODULE process)

# ....

# 定义如何安装
install(xxx bin)
install(xxx etc)
# ...
```
