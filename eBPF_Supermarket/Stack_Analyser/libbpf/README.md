# 运行方法

## 使用Ubuntu官方链接库编译

### 安装依赖

```shell
$ sudo apt update
$ sudo apt install clang libelf1 libelf-dev zlib1g-dev
$ sudo apt install libbpf-dev
$ sudo apt install linux-tools-5.19.0-46-generic	
$ sudo apt install linux-cloud-tools-5.19.0-46-generic
$ sudo apt install libc6-dev-i386
$ sudo cp FlameGraph/* /usr/bin/
```

### 工具编译

```shell
$ cd libbpf
$ sudo make
```

## 使用本地链接库编译

### 安装依赖

```shell
$ git submodule update --init --recursive
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

### 工具编译

```shell
$ cd libbpf
$ sudo make -f Makefile.new
```

### 运行

```shell
SYNOPSIS
    ./stack_analyzer on-cpu [-F <sampling frequency>] [-f] ([-p <pid of sampled process>] | [-c
        <to be sampled command to run>]) [-U] [-K] [-m <max threshold of sampled
        process>] [-n <min threshold of sampled process>] [-d <delay time to
        output>] [-r|-l] [<simpling time>] [-v]

    ./stack_analyzer off-cpu [-f] ([-p <pid of sampled process>] | [-c <to be sampled command to
        run>]) [-U] [-K] [-m <max threshold of sampled process>] [-n <min threshold
        of sampled process>] [-d <delay time to output>] [-r|-l] [<simpling time>]
        [-v]

    ./stack_analyzer mem [-f] ([-p <pid of sampled process>] | [-c <to be sampled command to
        run>]) [-U] [-K] [-m <max threshold of sampled process>] [-n <min threshold
        of sampled process>] [-d <delay time to output>] [-r|-l] [<simpling time>]
        [-v]

    ./stack_analyzer io [-C] [-f] ([-p <pid of sampled process>] | [-c <to be sampled command to
        run>]) [-U] [-K] [-m <max threshold of sampled process>] [-n <min threshold
        of sampled process>] [-d <delay time to output>] [-r|-l] [<simpling time>]
        [-v]

    ./stack_analyzer ra [-f] ([-p <pid of sampled process>] | [-c <to be sampled command to
        run>]) [-U] [-K] [-m <max threshold of sampled process>] [-n <min threshold
        of sampled process>] [-d <delay time to output>] [-r|-l] [<simpling time>]
        [-v]

OPTIONS
    on-cpu      sample the call stacks of on-cpu processes
    <sampling frequency>
    	sampling at a set frequency

    off-cpu     sample the call stacks of off-cpu processes
    mem         sample the memory usage of call stacks
    io          sample the IO data volume of call stacks
    -C, --in-count
    	sample the IO data in count instead of in size

    ra          sample the readahead hit rate of call stacks
    -f, --flame-graph
    	save in flame.svg instead of stack_count.json

    display mode (default none)
        -r, --realtime-draw
            draw flame graph realtimely

        -l, --realtime-list
        	output in console

    -v, --version
    	show version
```

# 运行效果

展示工具的输出格式及说明

### 实时输出测试结果

#### 升序列表形式

使用 `-l` 选项开启。
```shell
$ sudo ./stack_analyzer on-cpu
Thu Sep 28 16:57:47 2023
pid:24647       usid:56144      ksid:65341      value:1.00
pid:23844       usid:-14        ksid:127594     value:1.00
pid:14297       usid:84638      ksid:47805      value:1.00
pid:24658       usid:96121      ksid:-14        value:1.00
pid:9577        usid:16299      ksid:-14        value:1.00
pid:9577        usid:21537      ksid:-14        value:1.00
pid:9581        usid:34778      ksid:-14        value:1.00
pid:9582        usid:3180       ksid:-14        value:1.00
pid:24650       usid:71768      ksid:-14        value:1.00
Thu Sep 28 16:57:52 2023
pid:24647       usid:56144      ksid:65341      value:1.00
pid:23844       usid:-14        ksid:127594     value:1.00
pid:24671       usid:22828      ksid:70105      value:1.00
pid:14297       usid:84638      ksid:47805      value:1.00
pid:24658       usid:96121      ksid:-14        value:1.00
pid:9577        usid:16299      ksid:-14        value:1.00
pid:24641       usid:8523       ksid:-14        value:1.00
pid:14297       usid:24434      ksid:-14        value:1.00
pid:24672       usid:-14        ksid:75569      value:1.00
pid:9577        usid:21537      ksid:-14        value:1.00
pid:9581        usid:34778      ksid:-14        value:1.00
pid:24669       usid:23725      ksid:-14        value:1.00
pid:9580        usid:60903      ksid:-14        value:1.00
pid:9582        usid:3180       ksid:-14        value:1.00
pid:24650       usid:71768      ksid:-14        value:1.00
pid:24641       usid:8523       ksid:65355      value:3.00
```

代码示为采集on-cpu栈数据的实时输出，由时间戳分割，第一列为pid，第二三列为用户栈id和内核栈id，可以在程序结束后在json文件中找到其对应的栈；第四列为栈的数量，各子功能计数单位略有不同，on-cpu、io次数计数单位为次，off-cpu计数单位为0.1ms，数据量计数单位为字节，页面计数单位为页。

#### 火焰图形式

使用 `-r` 选项可使实时绘制火焰图替代列表形式，更容易直观地观察调用栈的变化情况。火焰图统一存储到 `flame.svg` 文件中，可以为此文件启用一个网络服务，便于实时地从浏览器中查看，例如：

```shell
python -m http.server 8000
echo please open http://localhost:8000/flame.svg
```

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

