### 安装依赖

```shell
$ git submodule update --init --recursive
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

### 版本要求

Linux 5.15以上
g++-10以上
clang-12以上

### 工具编译

客户端编译：

```shell
$ make
```

服务器端编译：

```shell
$ g++ server.cpp -o server
```

### 命令使用方法

客户端：

```shell
$ ./stack_analyzer -h
SYNOPSIS
        ./stack_analyzer ([-p <pid of sampled process, default -1 for all>] | [-c <to be sampled
                         command to run, default none>]) [-d <delay time(seconds) to output, default
                         5>] [-l] [-t <run time, default nearly infinite>] [-s <server address,
                         default 127.0.0.1:12345>] [-v] [on-cpu [-F <sampling frequency>] [-U] [-K]
                         [-m <max threshold of sampled value>] [-n <min threshold of sampled
                         value>]] [off-cpu [-U] [-K] [-m <max threshold of sampled value>] [-n <min
                         threshold of sampled value>]] [mem [-U] [-K] [-m <max threshold of sampled
                         value>] [-n <min threshold of sampled value>]] [io [--mod [count|ave|size]]
                         [-U] [-K] [-m <max threshold of sampled value>] [-n <min threshold of
                         sampled value>]] [ra [-U] [-K] [-m <max threshold of sampled value>] [-n
                         <min threshold of sampled value>]]

OPTIONS
        statistic call trace relate with some metrics
            -p, --pid <pid of sampled process, default -1 for all>
                    set pid of process to monitor

            -c, --command <to be sampled command to run, default none>
                    set command for monitoring the whole life

            -d, --delay <delay time(seconds) to output, default 5>
                    set the interval to output

            -l, --realtime-list
                    output in console, default false

            <run time, default nearly infinite>
                    set the total simpling time

            <server address, default 127.0.0.1:12345>
                    set the server address

            -v, --version
                    show version

            on-cpu  sample the call stacks of on-cpu processes
            <sampling frequency>
                    sampling at a set frequency

            -U, --user-stack-only
                    only sample user stacks

            -K, --kernel-stack-only
                    only sample kernel stacks

            -m, --max-value <max threshold of sampled value>
                    set the max threshold of sampled value

            -n, --min-value <min threshold of sampled value>
                    set the min threshold of sampled value

            off-cpu sample the call stacks of off-cpu processes
            -U, --user-stack-only
                    only sample user stacks

            -K, --kernel-stack-only
                    only sample kernel stacks

            -m, --max-value <max threshold of sampled value>
                    set the max threshold of sampled value

            -n, --min-value <min threshold of sampled value>
                    set the min threshold of sampled value

            mem     sample the memory usage of call stacks
            -U, --user-stack-only
                    only sample user stacks

            -K, --kernel-stack-only
                    only sample kernel stacks

            -m, --max-value <max threshold of sampled value>
                    set the max threshold of sampled value

            -n, --min-value <min threshold of sampled value>
                    set the min threshold of sampled value

            io      sample the IO data volume of call stacks
            --mod [count|ave|size]
                    set the statistic mod

            -U, --user-stack-only
                    only sample user stacks

            -K, --kernel-stack-only
                    only sample kernel stacks

            -m, --max-value <max threshold of sampled value>
                    set the max threshold of sampled value

            -n, --min-value <min threshold of sampled value>
                    set the min threshold of sampled value

            ra      sample the readahead hit rate of call stacks
            -U, --user-stack-only
                    only sample user stacks

            -K, --kernel-stack-only
                    only sample kernel stacks

            -m, --max-value <max threshold of sampled value>
                    set the max threshold of sampled value

            -n, --min-value <min threshold of sampled value>
                    set the min threshold of sampled value
```

服务器端：

```shell
$ ./server [port for listening, default 12345]
```

### 运行效果

开启服务器端，然后开启客户端，以on-cpu子功能为例：

服务器端：

```shell
$ ./server 
等待客户端连接...
客户端连接成功
on_cpu_stack_data.log
on_cpu_stack_data.log
on_cpu_stack_data.log
on_cpu_stack_data.log
连接关闭或出现错误
客户端连接成功
on_cpu_stack_data.log
on_cpu_stack_data.log
连接关闭或出现错误
^C
$ 
```

客户端：

```shell
$ sudo ./stack_analyzer on-cpu
display mode: 0
Thu Jan  4 19:45:03 2024
Thu Jan  4 19:45:09 2024
Thu Jan  4 19:45:14 2024
Thu Jan  4 19:45:19 2024
^C
$ sudo ./stack_analyzer on-cpu
display mode: 0
Thu Jan  4 19:45:45 2024
Thu Jan  4 19:45:51 2024
^C
$ 
```

保存的数据如下所示：

```log
cpptools:3394;sqlite3BtreeTableMoveto+0x7f677fa00000;---------;[MISSING KERNEL STACK]; 2
```

第一个分号前是命令名以及pid，之后是用户栈及内核栈，由“---------”分隔，末尾是调用栈对应的指标值，on-cpu子功能中表示5s内的定频采样数。

若客户端没有探测到服务端，则客户端会将数据存储在本地，并输出列表：

```shell
$ sudo ./stack_analyzer on-cpu
display mode: 0
Error connecting to server
Thu Jan  4 20:45:45 2024
pid:24647       usid:56144      ksid:65341      value:1.00
pid:23844       usid:-14        ksid:127594     value:1.00
pid:14297       usid:84638      ksid:47805      value:1.00
pid:24658       usid:96121      ksid:-14        value:1.00
pid:9577        usid:16299      ksid:-14        value:1.00
pid:9577        usid:21537      ksid:-14        value:1.00
pid:9581        usid:34778      ksid:-14        value:1.00
pid:9582        usid:3180       ksid:-14        value:1.00
pid:24650       usid:71768      ksid:-14        value:1.00
Thu Jan  4 20:45:51 2024
pid:24647       usid:56144      ksid:65341      value:1.00
pid:23844       usid:-14        ksid:127594     value:1.00
pid:24671       usid:22828      ksid:70105      value:1.00
pid:14297       usid:84638      ksid:47805      value:1.00
```