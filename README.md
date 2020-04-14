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
├── main  项目的主要应用
├── main/pkg  外部应用程序可以使用的库代码
├── vendor  项目依赖的其他第三方库
├── website  vue-element-admin
</code></pre>
</details>


## 感谢以下开源项目的支持

- [Gin] - [https://gin-gonic.com/](https://gin-gonic.com/)
- [bcc] - [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)