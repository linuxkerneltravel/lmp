# Linux microscope

## 项目目标

1. 帮助运维人员更全面地了解系统实时运行状态
2. 希望通过BPF技术来探测系统性能数据
3. 能够通过web形式展示性能数据



## startup

TODO...

## 项目架构

![](https://wx2.sinaimg.cn/mw690/005yyrljly1gdoj1zyuhsj31gd0u0apq.jpg)

## 界面截图

<details>
<summary>展开查看</summary>
<pre><code>
<img src="./static/imgs/homepage.png" width="2880" height="450" /><br/><br/>
</code></pre>
</details>


## 项目结构概览

<details>
<summary>展开查看</summary>
<pre><code>.
├── README.md
├── api   协议文件、前端交互的接口文件等
├── cmd   main函数文件目录
├── configs   配置文件
├── deployments   后端下发的一些配置文件与模板
├── docs   本项目设计文档，项目经历记录文档等
├── go.mod
├── go.sum
├── internal   本项目封装的代码，其中包括BPF代码等
├── pkg   通用的可以被其他项目所使用的一些代码
├── routers   本项目的路由设置与路由函数
├── static   项目用到的一些静态页面，包括前端静态展示页、图片等
├── test   测试目录，包括功能测试，性能测试等
└── vendor   本项目依赖的其它第三方库
</code></pre>
</details>

## 感谢以下开源项目的支持

- [Gin] - [https://gin-gonic.com/](https://gin-gonic.com/)
- [bcc] - [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)