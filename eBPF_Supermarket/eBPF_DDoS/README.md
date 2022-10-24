## lmpddos
基于eBPF的DDoS攻击检测和防御，每种类型的DDoS以插件的形式集成到lmpddos中

目前包含的插件有：
- DNS DDoS

### 前提
内核版本>=5.4，更低版本未验证

1. 已安装：
- Docker

2. 构建lmpddos镜像
```bash
docker build . -t lmpddos:1.0
```

### 快速开始
开启DNS DDoS防御
```bash
docker run --privileged --rm -it --name lmpddos -v /lib/modules:/lib/modules -v /usr/src:/usr/src -v /sys/kernel/debug:/sys/kernel/debug:rw -v /sys/fs/bpf:/sys/fs/bpf lmpddos:1.0 ./lmpddos -p dns load
```

关闭DNS DDoS防御
```bash
docker stop lmpddos
```

### 使用说明
使用`lmpddos load`命令开启DDoS防御，通过`-p`参数指定启用的插件，例如 
```bash
lmpddos load -p dns
```
查看lmpddos的帮助信息
```bash
docker run --privileged --rm -it --name lmpddos -v /lib/modules:/lib/modules -v /usr/src:/usr/src -v /sys/kernel/debug:/sys/kernel/debug:rw -v /sys/fs/bpf:/sys/fs/bpf lmpddos:1.0 ./lmpddos -h

LMP: ebpf programs for mitigating DDoS attacks.

Usage:
  lmpddos [flags]
  lmpddos [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  load        load ebpf programs to mitigate DDoS attacks
  unload      unload ebpf programs

Flags:
  -h, --help                  help for lmpddos
  -p, --plugins stringArray   available plugins: dns

Use "lmpddos [command] --help" for more information about a command.
```

### 添加新插件
DDoS攻击有很多种，用户可以开发自己的DDoS防御工具，以插件的形式集成到lmpddos中：

![](./bpf/dns-ddos/docs/images/ddos-plugin.jpg)

1. 将新插件的eBPF程序（内核态+用户态）添加到`bpf/xxx`目录下

2. 确定新插件的program index，该值应为当前所有插件的index的最大值+1，例如目前有2个插件，index分别为0和1，所以新程序的index应该为2

3. 在`pkg/ebpf`中新建一个文件，实现`Plugin`接口
```go
type Plugin interface {
	GetProgramIndex() uint32
	Load() error
	Run() error
	Unload() error
}
```
其中各方法的含义如下：
| 方法  |  含义 |
| ------------ | ------------ |
| GetProgramIndex  | 返回该eBPF程序的index（当前所有插件的index的最大值+1）  |
|  Load |  将xdp程序添加到`/sys/fs/bpf/xdp/globals/ddos_programs` bpf map中，key为程序的index，value为xdp程序 |
| Run  |  运行除xdp外的其他程序（例如在用户态提取指标等） |
| Unload  | 卸载插件时需要做的清理工作 |

4. 在`pkg/config/config.go`中修改`PluginMap`，添加一个条目，key为插件名称，value为上一步开发的插件

5. 在`main.go`的init函数中修改`plugins`可用参数的介绍，例如`available plugins: dns,xxx`


#### program index表
| 插件  |  index |
| :------------: | :------------: |
| DNS DDoS  |  1 |

#### 设置ebpf程序attach的interface
通过`LMP_DDOS_INTERFACE`环境变量指定，默认为`eth0`
