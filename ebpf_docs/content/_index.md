---
title: "LMP 项目介绍"
---

# LMP 项目介绍

LMP是一个基于BCC(BPF Compiler Collection)的Linux系统性能数据实时展示的web工具，它使用BPF(Berkeley Packet Filters)，也叫eBPF，目前LMP在ubuntu18.04上测试通过，内核版本4.15.0。

{{% notice tip %}}Learn theme works with a _page tree structure_ to organize content : All contents are pages, which belong to other pages. [read more about this]({{%relref "monitor/pages/_index.md"%}}) 
{{% /notice %}}

## Main features

* [Automatic Search]({{%relref "start/configuration/_index.md#activate-search" %}})
* [Multilingual mode]({{%relref "monitor/i18n/_index.md" %}})
* **Unlimited menu levels**
* **Automatic next/prev buttons to navigate through menu entries**
* [Attachments files]({{%relref "demo/attachments.md" %}})

## 代码结构
```
├── docs    # 文档
├── pkg     # golang 服务代码
├── plugins # python ebpf 代码
├── static  # 网页代码
├── test    # 测试数据
└── vendor  # golang vendor 
```
## 界面截图
![Screenshot](images/homepage.png)


## Contribute to this documentation
Feel free to update this content, just click the **Edit this page** link displayed on top right of each page, and pullrequest it

{{% notice info %}}
Your modification will be deployed automatically when merged.
{{% /notice %}}

## Documentation website
This current documentation has been statically generated with Hugo with a simple command : `hugo -t hugo-theme-learn` -- source code is [available here at GitHub](https://github.com/matcornic/hugo-theme-learn)

{{% notice note %}}
Automatically published and hosted thanks to [Netlify](https://www.netlify.com/). Read more about [Automated HUGO deployments with Netlify](https://www.netlify.com/blog/2015/07/30/hosting-hugo-on-netlifyinsanely-fast-deploys/)
{{% /notice %}}