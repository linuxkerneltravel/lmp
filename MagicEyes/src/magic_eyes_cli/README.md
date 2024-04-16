## magic_eyes_cli 命令行前端

### 1. 简述

将所有的后端工具统一到一个命令行前端，并且具备自动补全功能。

Tips：**记得Tab**

### 2. 使用之前

```bash
mkdir build && cd build
cmake .. && make && make install
cd ./install/magic_eyes_cli
# 运行前置条件脚本
source ./before_running.sh
```

### 3. 使用

```bash
(venv) $ ./magic_eyes_cli -h
/home/fzy/Downloads/04_bcc_ebpf/MagicEyes
usage: magic_eyes_cli [-h] [-l | -c] {net,memory,system_diagnosis,process} ...

magic_eyes_cli: command tools for Linux kernel diagnosis and optimization

positional arguments:
  {net,memory,system_diagnosis,process}
    net                 tool for Linux net subsystem
    memory              tool for Linux memory subsystem
    system_diagnosis    tool for Linux system_diagnosis subsystem
    process             tool for Linux process subsystem

optional arguments:
  -h, --help            show this help message and exit

all of common options:
  -l                    list all avaliable tools
  -c                    check all tools dependency, and whether it can be run in current platform

eg: magic_eyes_cli -l
```

**固定命令**

magic_eyes_cli具有2个固定命令， 即

```bash
-l : 即list， 列出所有可用的后端命令
-c : 即check， 检查所有运行依赖项（暂未实现）
```

**动态命令**

{net,memory,system_diagnosis,process}为动态命令，会根据backend文件夹下的情况动态调整。

### 4. 例程

```bash
magic_eyes_cli process cpu_watcher -h
# <------------------ 自动补全 | 非自动补全
```

### 5.其他

```bash
# 生成requirements.txt
pip3 freeze > requirements.txt
#  安装
pip3 install -r requiredments.txt
```
