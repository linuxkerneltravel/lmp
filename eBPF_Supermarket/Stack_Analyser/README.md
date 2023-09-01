# 功能描述

对操作系统各方面的调用栈进行计数，从中分析程序性能瓶颈。

# 运行方法

## libbpf版

轻量，功能较少

### 安装依赖

```shell
sudo apt update
sudo apt install clang libelf1 libelf-dev zlib1g-dev
sudo apt install libbpf-dev
sudo apt install linux-tools-5.19.0-46-generic	
sudo apt install linux-cloud-tools-5.19.0-46-generic
sudo apt install libc6-dev-i386
sudo cp FlameGraph/* /usr/bin/
```

### 工具编译

```shell
cd libbpf
sudo make
```

### 运行

```shell
SYNOPSIS
        ./stack_analyzer on-cpu [-F <sampling frequency>] [-f] [-p <set the pid of sampled process>]
                         [-U] [-K] [<simpling time>] [-v]

        ./stack_analyzer off-cpu [-f] [-p <set the pid of sampled process>] [-U] [-K] [<simpling
                         time>] [-v]

        ./stack_analyzer mem [-f] [-p <set the pid of sampled process>] [-U] [-K] [<simpling time>]
                         [-v]

        ./stack_analyzer io [-f] [-p <set the pid of sampled process>] [-U] [-K] [<simpling time>]
                         [-v]

OPTIONS
        on-cpu      sample the call stacks of on-cpu processes
        <sampling frequency>
                    sampling at a set frequency

        off-cpu     sample the call stacks of off-cpu processes
        mem         sample the memory usage of call stacks
        io          sample the IO data volume of call stacks
        -v, --version
                    show version
```

## bcc版

消耗较大，但功能较强，结合机器学习pca算法进行栈分析

### 安装依赖

```shell
python -m pip install --upgrade pip
sudo python -m pip install pyod
sudo python -m pip install psutil
sudo apt-get install -y linux-headers-$(uname -r)
sudo apt-get install -y python-is-python3
sudo apt-get install -y bison build-essential cmake flex git libedit-dev libllvm11 llvm-11-dev libclang-11-dev zlib1g-dev libelf-dev libfl-dev python3-distutils
sudo ln -s /usr/lib/llvm-11 /usr/local/llvm
```

### 编译依赖

```shell
cd bcc
wget https://github.com/iovisor/bcc/releases/download/v0.25.0/bcc-src-with-submodule.tar.gz
tar xf bcc-src-with-submodule.tar.gz
cd bcc/
mkdir build
cd build/
cmake -DCMAKE_INSTALL_PREFIX=/usr -DPYTHON_CMD=python3 ..
make
sudo make install
cd ../../
```

### 运行

stack_analyzer

```shell
usage: stack_count.py [-h] [-p PID | -t TID | -c Command | -u | -k] [-U | -K] [-a] [-d] [-f] [-s] [-m MODE] [--stack-storage-size STACK_STORAGE_SIZE]
                      [--state STATE]
                      [duration]

Summarize on-CPU time by stack trace

positional arguments:
  duration              duration of trace, in seconds

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     trace this PID only
  -t TID, --tid TID     trace this TID only
  -c Command, --cmd Command
                        trace this command only
  -u, --user-threads-only
                        user threads only (no kernel threads)
  -k, --kernel-threads-only
                        kernel threads only (no user threads)
  -U, --user-stacks-only
                        show stacks from user space only (no kernel space stacks)
  -K, --kernel-stacks-only
                        show stacks from kernel space only (no user space stacks)
  -a, --auto            analyzing stacks automatically
  -d, --delimited       insert delimiter between kernel/user stacks
  -f, --folded          output folded format
  -s, --offset          show address offsets
  -m MODE, --mode MODE  mode of stack counting, 'on_cpu'/'off_cpu'/'mem'
  --stack-storage-size STACK_STORAGE_SIZE
                        the number of unique stack traces that can be stored and displayed (default 16384)
  --state STATE         filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE) see include/linux/sched.h

examples:
    sudo -E ./stack_count.py             # trace on-CPU stack time until Ctrl-C
    sudo -E ./stack_count.py -m off_cpu  # trace off-CPU stack time until Ctrl-C
    sudo -E ./stack_count.py 5           # trace for 5 seconds only
    sudo -E ./stack_count.py -f 5        # 5 seconds, and output as stack_count.svg in flame graph format
    sudo -E ./stack_count.py -s 5        # 5 seconds, and show symbol offsets
    sudo -E ./stack_count.py -p 185      # only trace threads for PID 185
    sudo -E ./stack_count.py -t 188      # only trace thread 188
    sudo -E ./stack_count.py -c cmdline  # only trace threads of cmdline
    sudo -E ./stack_count.py -u          # only trace user threads (no kernel)
    sudo -E ./stack_count.py -k          # only trace kernel threads (no user)
    sudo -E ./stack_count.py -U          # only show user space stacks (no kernel)
    sudo -E ./stack_count.py -K          # only show kernel space stacks (no user)
    sudo -E ./stack_count.py -a          # anomaly detection for stack
```

load_monitor，计划将该工具以阈值控制选项的形式与stack_analyzer合并

```shell
usage: load_monitor.py [-h] [-t TIME] [-F FREQ] [-d DELAY] [-l THRESHOLD] [-r]

Summarize on-CPU time by stack trace

options:
  -h, --help            show this help message and exit
  -t TIME, --time TIME  running time
  -F FREQ, --frequency FREQ
                        monitor frequency
  -d DELAY, --delay DELAY
                        output delay(interval)
  -l THRESHOLD, --threshold THRESHOLD
                        load limit threshold
  -r, --report

examples:
        ./load_monitor.py             # monitor system load until Ctrl-C
        ./load_monitor.py -t 5           # monitor for 5 seconds only
```

# 运行效果

展示工具的输出格式及说明

## stack_analyzer

采集在线的、离线的、内存申请释放、读写等调用栈。

### 实时输出测试结果

```shell
Stack_Analyser/libbpf$ sudo ./stack_analyzer -p 12532
---------7---------
12532  ( 38758,118464) 1     
12532  ( 77616, 97063) 1     
12532  (   -14,116464) 1     
12532  (   -14, 18600) 1     
12532  ( 31291, 87833) 1     
---------5---------
---------7---------
12532  (    -1, 91718) 3482309
12532  (    -1, 38038) 3533633
12532  (    -1, 89746) 377229951
12532  (    -1, 83783) 2977594
```

代码示为on-cpu、off-cpu和内存栈数据分别采集stress-ng-malloc 5s的输出，由分割线分开，分割线中间的数字为map fd，分割线间，第一列为pid，第二列括号中用户栈id和内核栈id，第三列为栈的数量，计数单位略有不同，on-cpu计数单位为次，off-cpu计数单位为0.1ms，内存计数单位为1kB

### json文件结果

```json
{
    "12532": {
        "12532": {
            "stacks": {
                "91718,-1": {
                    "count": 3482309,
                    "trace": [
                        "MISSING KERNEL STACK",
                        "stress_malloc_loop"
                    ]
                }
            },
            "name": "stress-ng-mallo"
        }
    }
}
```

以上代码为保存的json文件片段展开后的内容，是一个跟踪stress-ng-malloc采集到的内存栈信息，其内核栈标注为"MISSING KERNEL STACK"，表示内核栈没有被采集。

## bcc/load_monitor.py

用于在计算机负载超过阈值时记录内核栈数量信息，每5s输出一次总记录。

终止时将记录以 栈-数量 的格式保存在 `./stack.bpf` 中，并输出火焰图文件 `./stack.svg`

## 输出片段

屏幕输出：
```log
____________________________________________________________
0xffffffff928fced1 update_rq_clock
0xffffffff92904c34 do_task_dead
0xffffffff928c40a1 do_exit
0xffffffff928c421b do_group_exit
0xffffffff928d5280 get_signal
0xffffffff9283d6ce arch_do_signal_or_restart
0xffffffff9296bcc4 exit_to_user_mode_loop
0xffffffff9296be00 exit_to_user_mode_prepare
0xffffffff9359db97 syscall_exit_to_user_mode
0xffffffff93599809 do_syscall_64
0xffffffff93600099 entry_SYSCALL_64_after_hwframe
stackid    count  pid    comm            
5          37    
                  82731  5               
                  82783  IPC I/O Parent  
                  82794  TaskCon~ller #1 
                  82804  pool-spawner    
                  82830  Breakpad Server 
                  82858  Socket Thread   
                  82859  JS Watchdog     
                  82860  Backgro~Pool #1 
                  82861  Timer           
                  82862  RemVidChild     
                  82863  ImageIO         
                  82864  Worker Launcher 
                  82865  TaskCon~ller #0 
                  82867  ImageBridgeChld 
                  82869  ProfilerChild   
                  82870  AudioIP~ack RPC 
                  82871  AudioIP~ver RPC 
                  82877  dconf worker    
                  82885  snap            
                  83010  StreamTrans #1  
                  83011  StreamTrans #2  
                  83018  StreamTrans #3  
                  83020  StreamTrans #5  
                  83029  JS Watchdog     
                  83030  Backgro~Pool #1 
                  83031  Timer           
                  83033  ImageIO         
                  83034  Worker Launcher 
                  83036  TaskCon~ller #1 
                  83037  ImageBridgeChld 
                  83048  IPC I/O Child   
                  83049  Socket Thread   
                  83051  Backgro~Pool #1 
                  83052  Timer           
                  83053  RemVidChild     
                  83055  TaskCon~ller #0 
                  83059  ProfilerChild   
____________________________________________________________
```

文件输出：
```log
@[
update_rq_clock
sched_autogroup_exit_task
do_exit
do_group_exit
get_signal
arch_do_signal_or_restart
exit_to_user_mode_loop
exit_to_user_mode_prepare
syscall_exit_to_user_mode
do_syscall_64
entry_SYSCALL_64_after_hwframe
]: 37
```
<center><img src="assets/stack.svg" alt="stack.svg" style="zoom:90%;" /></center>


# 计划安排

- [x] 实时输出功能
- [x] on-cpu 栈采集功能
- [x] off-cpu 栈采集功能
- [x] malloc-free 栈采集功能
- [x] 保存为json文件功能
- [x] 火焰图绘制功能
- [x] io-write栈采集功能
- [x] 加入排序功能
- [ ] 收发包栈采集功能
- [ ] 兼容perf数据
- [ ] 栈数据智能分析功能
- [ ] 解决保存数据时卡顿的问题