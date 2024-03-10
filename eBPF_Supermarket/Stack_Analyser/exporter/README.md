# 功能描述

适用于Pyroscope服务器的数据发送程序，程序通过监听标准输入来获取调用栈数据，输入格式与stack_analyzer工具输出格式一致，可通过管道配合stack_analyer使用，将stack_analyzer的数据发送到Pyroscope服务器获取更强的数据存储和可视化能力。

# 使用方法

若在该文件所在目录exporter下进行。

## 构建

```shell
go build
```

## 命令参数

```shell
./exporter --help
```

## 使用方法

```shell
sudo ../stack_analyzer [option..] | ./exporter
```