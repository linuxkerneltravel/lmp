# frida——一种利用native hook技术的工具

## 1、安装

```c
//使用pip安装frida
pip install frida-tools
```

## 2、打开ptrace跟踪设置

```c
sudo sysctl kernel.yama.ptrace_scope=0
```

## 3、运行“cat”命令的跟踪函数

```
python cat.py
```

## 4、输出结果

```c
//下面输出的是"cat"进程执行时加载的一些共享库和系统库
  print([m["name"] for m in script.exports.enumerate_modules()])
['cat', 'linux-vdso.so.1', 'libc.so.6', 'ld-linux-x86-64.so.2', 'libdl.so.2', 'librt.so.1', 'libm.so.6', 'libpthread.so.0']
```

