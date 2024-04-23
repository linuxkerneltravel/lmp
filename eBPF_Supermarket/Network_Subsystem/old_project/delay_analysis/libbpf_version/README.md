# delay_analysis libbpf version

### 1. 编译
```bash
# lmp目录下，下载子模块
git submodule update --init --recursive
# 编译
make
# 清除
make clean
```

### 2. 运行
```bash
# 帮助
./delay_analysis --help

Usage: delay_analysis [OPTION...]
Trace time delay in network subsystem 

  -6, --ipv6=IPV6            0:ipv4, 1:ipv6, ipv4 is default
  -c, --count=COUNT          count of outputs
  -d, --dport=DPORT          trace this destination port only
  -O, --Out=OUT              in/out(1/0),default is in
  -s, --sport=SPORT          trace this source port only
  -S, --sample=SAMPLING      Trace sampling
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```
例如, 捕捉发送路径及ipv6的网络数据包，可以使用：  `./delay_analysis -O 1 -6 1`

### 3. 目前缺陷
1. 因编译器导致的部分kprobe点具有后缀 isra.0，后续需解决兼容性问题