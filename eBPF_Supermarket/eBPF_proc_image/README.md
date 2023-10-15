# 基于eBPF的Linux系统性能监测工具-进程画像

## 一、介绍

本项目是一个Linux进程生命周期画像工具，通过该工具可以清晰展示出一个进程从创建到终止的完整生命周期，并可以额外展示出进程/线程持有锁的区间画像、进程/线程上下文切换原因的标注、线程之间依赖关系（线程）、进程关联调用栈信息标注等。在这些功能的前提下，加入了更多的可视化元素和交互方式，使得整个画像更加直观、易于理解。

运行环境：Ubuntu 22.04，内核版本5.19.0-46-generic

## 二、安装依赖

```
sudo apt update
sudo apt install libbpf-dev clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
git submodule update --init --recursive
```

## 三、proc_image 工具

目前 proc_image 工具具备的功能：

- 记录进程上下CPU的时间信息
- 记录进程的关键时间点信息，即exec和exit
- 记录进程持有锁的区间信息，目前实现了用户态互斥锁、内核态互斥锁、用户态读写锁
- 记录新创建进程或线程的时间信息

proc_image 工具的参数信息：

| 参数                 | 描述                                              |
| -------------------- | ------------------------------------------------- |
| -p, --pid=PID        | 指定跟踪进程的pid，默认为0号进程                  |
| -t, --time=TIME-SEC  | 设置程序的最大运行时间（0表示无限），默认一直运行 |
| -C, --cpuid=CPUID    | 为每CPU进程设置，其他进程不需要设置该参数         |
| -c, --cputime        | 统计进程上下CPU时间信息                           |
| -e, --execve         | 对进程execve关键时间点进行画像                    |
| -E, --exit           | 对进程exit关键时间点进行画像                      |
| -q, --quote          | 在参数周围添加引号(")                             |
| -K, --keytime        | 对进程的关键时间点进行画像，即execve和exit        |
| -m, --user-mutex     | 对进程的用户态互斥锁进行画像                      |
| -M, --kernel-mutex   | 对进程的内核态互斥锁进行画像                      |
| -r, --user-rwlock-rd | 对进程用户态读模式下的读写锁进行画像              |
| -w, --user-rwlock-wr | 对进程用户态写模式下的读写锁进行画像              |
| -L, --lock           | 对进程的各种锁进行画像                            |
| -f, --fork           | 对fork出来的子进程进行画像                        |
| -F, --vfork          | 对vfork出来的子进程进行画像                       |
| -T, --newthread      | 对pthread_create出来的新线程进行画像              |
| -S, --child          | 对新创建进程和线程进行画像                        |
| -A, --all            | 开启所有的功能                                    |
| -h, --help           | 显示帮助信息                                      |

用户态的自旋锁和信号量，在libbpf程序的开发过程中遇到了 libbpf: elf: ambiguous match  问题，目前这个问题社区也在讨论中，详情见 [libbpf_ambiguous_match_question.md](./docs/libbpf_ambiguous_match_question.md)。

## 四、newlife_image 工具

newlife_image工具可以对指定进程fork或vfork出来的新进程以及pthread_create出来的新线程进行画像。

newlife_image 工具采集到的数据：

1. newlife的产生方式以及newlife的pid
2. newlife的开始时间
3. newlife的退出时间
4. newlife的存在时间

newlife_image 工具的参数信息：

| 参数                | 描述                                              |
| ------------------- | ------------------------------------------------- |
| -p, --pid=PID       | 指定跟踪进程的pid，默认为0号进程                  |
| -t, --time=TIME-SEC | 设置程序的最大运行时间（0表示无限），默认一直运行 |
| -f, --fork          | 对fork出来的子进程进行画像                        |
| -F, --vfork         | 对vfork出来的子进程进行画像                       |
| -T, --newthread     | 对pthread_create出来的新线程进行画像              |
| -h, --help          | 显示帮助信息                                      |

问题及解决：

pthread_create函数也存在模糊匹配问题，如下：

```
libbpf: elf: ambiguous match for 'pthread_create', 'pthread_create' in '/usr/lib/x86_64-linux-gnu/libc.so.6'
```

在Ubuntu22.04.1中 fork 和 vfork 调用的都是clone系统调用，而 pthread_create 调用的是 clone3 系统调用，因此暂用 clone3 监控新线程。

## 五、proc_offcpu_time工具

该工具可通过-p参数指定进程的pid，便可以采集到该进程处于off_CPU的时间。该功能已经和加入sleep逻辑的用户态程序（./test/test_sleep.c）进行了时间上的比对，准确性满足要求。示例如下：

终端1：./test_sleep

```
test_sleep进程的PID：9063
输入任意数字继续程序的运行：
```

终端2：现在已知test_sleep进程的PID为9063，执行指令sudo ./proc_image -p 9063进行跟踪

终端1：输入任意数字继续程序的运行

最后终端1和终端2的运行结果如下：

```
// 终端1
test_sleep进程的PID：9063
输入任意数字继续程序的运行：1
程序开始执行...
sleep开始时间：2023-07-24 16:58:28
sleep结束时间：2023-07-24 16:58:31
程序睡眠3s，执行完毕！

//终端2
pid:9063  comm:test_sleep  offcpu_id:3  offcpu_time:5963882827916  oncpu_id:3  oncpu_time:5966883001411  sleeptime:3.000173
```

目前该工具的功能已经合入proc_image。

## 六、test_proc 测试程序 

目前 [test_proc](./test/test_proc.c) 测试程序所具备逻辑：

- 逻辑1：加入sleep逻辑使进程睡眠3秒，即offCPU 3秒
- 逻辑2：加入互斥锁逻辑，为了应对复杂场景，模拟进程异常地递归加锁解锁
- 逻辑3：加入fork和vfork逻辑，创建子进程让子进程睡眠3秒，以表示它存在的时间
- 逻辑4：加入pthread_create逻辑，创建线程让线程睡眠3秒，以表示它存在的时间
- 逻辑5：加入读写锁逻辑，在读模式或写模式下上锁后睡眠3s，以表示持有锁时间
- 逻辑6：加入execve逻辑，用于测试采集到数据的准确性
- 逻辑7：加入exit逻辑，可以手动输入程序退出的error_code值
