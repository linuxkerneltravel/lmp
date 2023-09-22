# 运行方法

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
$ ./stack_analyzer -h
SYNOPSIS
        ./stack_analyzer on-cpu [-F <sampling frequency>] [-f] ([-p <set the pid of sampled
                         process>] | [-c <set the sampled command to run>]) [-U] [-K] [<simpling
                         time>] [-v]

        ./stack_analyzer off-cpu [-f] ([-p <set the pid of sampled process>] | [-c <set the sampled
                         command to run>]) [-U] [-K] [<simpling time>] [-v]

        ./stack_analyzer mem [-f] ([-p <set the pid of sampled process>] | [-c <set the sampled
                         command to run>]) [-U] [-K] [<simpling time>] [-v]

        ./stack_analyzer io [-f] ([-p <set the pid of sampled process>] | [-c <set the sampled
                         command to run>]) [-U] [-K] [<simpling time>] [-v]

        ./stack_analyzer ra [-f] ([-p <set the pid of sampled process>] | [-c <set the sampled
                         command to run>]) [-U] [-K] [<simpling time>] [-v]

OPTIONS
        on-cpu      sample the call stacks of on-cpu processes
        <sampling frequency>
                    sampling at a set frequency

        off-cpu     sample the call stacks of off-cpu processes
        mem         sample the memory usage of call stacks
        io          sample the IO data volume of call stacks
        ra          sample the readahead hit rate of call stacks
        -v, --version
                    show version
```

# 运行效果

展示工具的输出格式及说明

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

## 火焰图文件结果

<center><img src="../assets/stack.svg" alt="stack.svg" style="zoom:90%;" /></center>