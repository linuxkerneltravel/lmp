# eBPF-utrace

[![Github Actions](https://github.com/linuxkerneltravel/lmp/actions/workflows/user_function_tracer.yml/badge.svg)](https://github.com/linuxkerneltravel/lmp/actions/workflows/user_function_tracer.yml)

## Introduction

`eBPF-utrace` is an eBPF-based user function tracer targeted for C/C++ programs. It offers function-level insights into program execution **without** requiring
recompilation, and can be used for debugging or performance analysis.

### Overview

[![eBPF-utrace-over.md.png](https://z1.ax1x.com/2023/10/07/pPjEPPJ.md.png)](https://imgse.com/i/pPjEPPJ)

### Screenshot

[![eBPF-utrace-screen.md.png](https://z1.ax1x.com/2023/10/11/pPzXQW6.md.png)](https://imgse.com/i/pPzXQW6)

[![flame-graph.jpg](https://z1.ax1x.com/2023/10/11/pPzXMJx.md.jpg)](https://imgse.com/i/pPzXMJx)

## Getting Started

### Install Dependencies

```shell
sudo apt install -y clang cmake ninja-build libelf-dev libbpf-dev linux-tools-$(uname -r)
```

WSL2 users also need to follow [tutorials to enable eBPF on WSL2](https://gist.github.com/MarioHewardt/5759641727aae880b29c8f715ba4d30f),
and then install bpftool manually.

```shell
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
sudo make install
```

### Build

```shell
mkdir -p vmlinux
bash tools/gen_vmlinux_h.sh > vmlinux/vmlinux.h
cmake -B build -S . -G Ninja
cmake --build build
build/utrace --help # see the detailed usage
```

### Running Examples

```shell
sudo build/utrace -c "./sort -n 5000" # use "-c" to specify the command to run the traced program
sudo build/utrace -p 2954 # use "-p" to specify the process ID of the traced program
sudo build/utrace --record -c "./sort -n 5000"
du -bh ./utrace.data # pre-traced data is recorded here
build/utrace --report --format=summary # see function-level analysis
build/utrace --report --format=flame-graph --output=./stack
git clone https://github.com/brendangregg/FlameGraph --depth=1
FlameGraph/flamegraph.pl ./stack > ./flame.svg # see high-level view
```

## Feature Highlight

- It is non-intrusive and does not require recompilation.
- It supports multi-threaded programs.
- It can attach to a running process.
- It provides real-time trace output instead of waiting for the traced program to finish.
- It offers many options for filtering out unnecessary functions, to improve performance and help analysis.
- It only relies on (1) the symbol tables (unstripped binary) for looking up traced functions and resolving runtime addresses,
and (2) PLT indirect call instructions (compiled with the `-fplt` option added by default) for tracing library calls.
That is, it can normally trace programs compiled with various optimizations (`-Ofast`) and without any debug info (`-g`).

## Comparisions

- `ftrace`: `eBPF-utrace` focuses on **user-space** functions, including library calls, rather than kernel-space functions.
- `uftrace`: `eBPF-utrace` utilizes the eBPF technology provided by Linux kernel, thus does **not rely on** any compilation options, but has a relatively higher overhead (~10x).
- `perf`, `gprof`: `eBPF-utrace` offers function-level tracing, which can accurately measure the execution time of **each** function call (although there has overhead),
rather than using approximate sampling methods.

## Overhead

It brings an overhead of around **10us** on a native Linux machine/WSL2 and 20us on a virtual machine for each traced function.

You can verify this by running `test/bench.cpp` yourself.

```shell
g++ test/bench.cpp -o test/bench
sodo build/utrace -c test/bench --output=/dev/null
```

To trace big projects like `LevelDB` and `Redis`, I recommend the following workflow:

1. Run `build/utrace --record -c/-p` and `build/utrace --report --format=summary`
to get basic insights into the traced program.

2. Re-run `build/utrace -c/-p` with `--function`, `--no-function`, `--lib` and `--no-lib` options
to filter out frequently called but uninteresting functions and thus
reduce the number of traced functions to an acceptable range (~1000).

## Limitations

- It breaks exception handling (and `setjmp`) due to issues caused by uretprobe. Similarly, coroutines that using context switch may be broken.
- It currently requires root permission, to be precise, the CAP_BPF capabality.
- It currently requires a large number of file descriptors. Each uprobe/uretprobe requires 2 fds (one for perf_event, and one for bpf), i.e.,
to trace one function, it needs 4 fds. Additionally, it takes about 30ms to detach one uprobe/uretprobe, so it may take a long time to detach
after finishing the tracing. (this issue can be solved by uprobe_multi starting from Linux 6.6)
- It cannot trace functions dynamically loaded by `dlsym` during runtime.
- Similar to `GDB` and `strace`, it cannot automatically trace forked child processes.
One solution is to manually attach to the child using another `eBPF-utrace` instance.
- So far, it has only been tested with executables compiled using clang, gcc, or musl-gcc on x86 (32 or 64-bit).
