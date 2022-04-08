## eBPF_observability 项目

该项目的目标是收集梳理基于 eBPF 的可观测性组件，从各种实现方式，各个角度对内核进行可观测。

欢迎大家体验使用这里的组件，更欢迎大家贡献更多的基于 eBPF 的可观测性程序。

## 类型介绍
|类型|介绍|备注|
|-|-|-|
|BCC|BCC 的 eBPF 可观测性程序||
|C|使用 C 开发的 eBPF 可观测性程序||
|GO|使用 GO 开发的 eBPF 可观测性程序||
|RUST|使用 RUST 开发的 eBPF 可观测性程序||

## 贡献方式
1. 根据自己的想法创建项目，完成 mvp。
2. 对应开发的程序进行文档撰写，后期研发目标的制定和研发计划制定。
3. 同时提交程序和文档。
4. 修改本 README 添加插件介绍和填写负责人信息。

## 该部分程序研发规范
1. 程序主要目标是通过 eBPF 程序采集内核的相关指标
2. 指标数据采集之后输出方式：
   1. 直接输出到标准输出
   2. 采集数据写入 influxdb
3. 代码中需要注明代码开发者
BCC:
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : ${DATE} ${TIME}
# @Author  : email地址，例如：helight@qq.com
# @FileName: ${NAME}.py
# @Software: LMP
```
GO:
```
# @Time    : ${DATE} ${TIME}
# @Author  : email地址，例如：helight@qq.com
# @FileName: ${NAME}.py
# @Software: LMP
```

## BCC eBPF 程序介绍
### cpu 相关程序
|程序|介绍|负责人|
|-|-|-|
||||
||||
||||
### 文件系统相关程序
|程序|介绍|负责人|
|-|-|-|
||||
||||
||||
### 内存相关程序
|程序|介绍|负责人|
|-|-|-|
||||
||||
||||
### 网络相关程序
|程序|介绍|负责人|
|-|-|-|
||||
||||
||||

## GO eBPF 程序介绍
|程序|介绍|负责人|
|-|-|-|
|[ciliumkprobe](go/ciliumkprobe/)|||
|[gobpfexecsnoop](go/gobpfexecsnoop/)|||
||||