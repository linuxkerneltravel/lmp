## 基于eBPF观测用户态函数时延和调用栈 (eBPF-utrace)

### 简介
借助eBPF用户态探针`uprobe`和`uretprobe`实现实时观测C/C++程序或者已运行进程中的用户态函数的调用时延以及调用栈，
从而清晰地了解一个程序的运行情况及其性能瓶颈。

### 安装依赖
```shell
sudo apt install -y clang cmake ninja-build libelf1 libelf-dev zlib1g-dev libbpf-dev linux-tools-$(uname -r) linux-cloud-tools-$(uname -r)
```

### 编译运行
```shell
$ mkdir -p vmlinux
$ bash tools/gen_vmlinux_h.sh > vmlinux/vmlinux.h
$ cmake -B build -S . -G Ninja
$ cmake --build build
$ build/utrace -h
Usage: build/utrace [$OPTIONS...]

Options:
  -c --command: the command to run the program to be traced.
  -p --pid: the PID of the program to be traced.
  -d --debug: enable debug mode.
     --no-ASLR: disable Address Space Layout Randomization (ASLR).
  -h --help: disaply this usage information.

Examples:
  build/utrace -c "$PROGRAM $ARGS"
  build/utrace -p $PID
```

### 特点
+ 不同于`ftrace`，`eBPF-utrace`用于观测用户态函数。
+ 不同于`uftrace`，`eBPF-utrace`基于eBPF，不依赖于任何编译技术，但是需要内核的支持，需要root权限，且可能有更高的开销。
+ 不同于`perf`, `gprof`等性能分析工具，`eBPF-utrace`输出准确的函数调用时延，而不是基于perf_event()的采样方式。

### TODO
- simplify c++ symbols
- more tests
- multithread
