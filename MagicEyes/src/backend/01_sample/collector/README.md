存放用于适配bridge的collector
1. 【数据转换】 项目组按照项目要求与后端输出形式，将后端数据转换为前端需要的数据
2. 【数据库存取】
3. 将文件（如fs_watcher_collector.py/go）软链接到 bridge/third_apps/fs下
3. bridge将自动查找所有的collector，并运行