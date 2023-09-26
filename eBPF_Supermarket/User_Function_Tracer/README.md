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
$ build/utrace --help
Usage: utrace [OPTION...]

eBPF-utrace: eBPF-based user function tracer for C/C++.

Examples:
  # trace the program specified by COMMAND
  $ sudo build/utrace -c "$COMMAND"
  # trace the program specified by PID
  $ sudo build/utrace -p $PID

  -c, --command=COMMAND      Specify the COMMAND to run the traced program
                             (format: "program arguments")
      --cpuid                Display CPU ID
  -d, --debug                Show debug information
      --flat                 Display in a flat output format
  -f, --function=FUNC_PATTERN   Only trace functions matching FUNC_PATTERN (in
                             glob format, default "*")
  -l, --lib=LIB_PATTERN      Only trace libcalls to libraries matching
                             LIB_PATTERN (in glob format, default "*")
      --libname              Append libname to symbol name
      --max-depth=DEPTH      Hide functions with stack depths greater than
                             DEPTH
      --nest-lib=NEST_LIB_PATTERN
                             Also trace functions in libraries matching
                             LIB_PATTERN (default "")
      --no-function=FUNC_PATTERN   Don't trace functions matching FUNC_PATTERN
                             (in glob format, default "")
      --no-randomize-addr    Disable address space layout randomization (ASLR)
  -o, --output=OUTPUT_FILE   Send trace output to OUTPUT_FILE instead of
                             stderr
  -p, --pid=PID              PID of the traced program
      --tid                  Display thread ID
      --time-filter=TIME     Hide functions when they run less than TIME
      --timestamp            Display timestamp
  -u, --user=USERNAME        Run the specified command as USERNAME
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

### 特点
- 观测用户态函数调用流程以及调用时延
- 非侵入式，不依赖任何编译选项
- 支持多线程程序、已经运行的程序（输入进程PID号）
+ 不同于`ftrace`，`eBPF-utrace`用于观测用户态函数。
+ 不同于`uftrace`，`eBPF-utrace`基于eBPF，不依赖于任何编译技术，但是需要内核的支持，需要root权限。
+ 不同于`perf`, `gprof`等性能分析工具，`eBPF-utrace`输出准确的函数调用时延，而不是基于perf_event的采样方式。

### TODO
- 嵌套的共享库观测
- 更多的测试
