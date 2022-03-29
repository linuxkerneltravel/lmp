---
title: 文档撰写规范
disableToc: true
---

## 文档存储地址
{{% notice warning %}}
所有文档都在 `lmp/docs/content/` 下面。
{{% /notice %}}

## `lmp/docs/content/` 目前结构
```
├── actions    # 该目录下面都是内核控制 `eBPF` 程序的文档，以及相关说明文档
├── demo       # 该目录下面都是文档撰写样式的 demo
├── monitor    # 该目录下面都是内核可观测 `eBPF` 程序的文档，以及相关说明文档
├── start      # 该目录下面是关于 `LMP` 项目的介绍，上手说明文档。
└── docstyle.en.md  # 文档规范说明
```
## 文档目录规范
{{% notice info %}}必要说明：
{{% /notice %}}

1. 文件夹和文件名必须是英文字母，需要分割可使用下划线，不能使用中文和其它符号。
2. 每个文档一个文件夹，内部包含一个 `images` 文件夹和 `_index.md` 文件。
3. `_index.md` 文件中引用的图片必须是本文件夹中 `images` 文件夹下的图片文件，不可引用外部图片。


例如 `start` 目录下的所有文档，都是具有独立目录：
```
➜  content git:(master) ✗ tree start
start
├── _index.md
├── architecture
│   ├── _index.md
│   └── images
│       └── magic.gif
├── configuration
│   ├── _index.md
│   └── images
│       └── home_button_defaults.jpg
├── installation
│   ├── _index.md
│   └── images
│       └── chapter.png
```

## 文档内容规范
以插件文档为例：

```md
## 插件说明
说明插件的一些基本情况

## 插件功能说明
插件的整体功能说明
### 插件功能1
插件基本功能 1 介绍
### 插件功能2
插件基本功能 2 介绍

## 插件代码解读
xxxx
### 插件功能代码1
插件基本功能 1 相关代码解读

### 插件功能代码2
插件基本功能 2 相关代码解读

## 插件使用
### 后台运行方式
直接命令行运行 python 的方式来执行该 eBPF 程序。
### web 运行方式
通过网页页面运行 eBPF 程序。
### 和 Prometheus、Grafana 联动
无论是后台还是 web 方式，数据可以写入 Prometheus，并且可以用 Grafana 展示数据。

这里最好把 Grafana 的报表导出来放在这里

## 插件运行版本
### 插件适用版本
插件理论上适合的版本
### 已经测试过的版本
已经测试过的版本

## 总结

## 额外说明
```

## 其它规范
暂无