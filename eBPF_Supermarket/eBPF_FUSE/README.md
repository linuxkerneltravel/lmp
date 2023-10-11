# boke

个人博客

## 项目1、eBPF_FUSE：使用eBPF优化FUSE read方法性能

### 项目描述：

​		FUSE（Filesystem in Userspace）是一个常用的用户空间文件系统框架，它允许用户空间程序实现自己的文件系统，并且可以通过内核的VFS（Virtual File System）接口进行挂载和管理。但是，FUSE存在性能瓶颈，其中之一就是在文件读取时存在内存拷贝，特别是在大量的小文件读取场景。

​		eBPF（Extended Berkeley Packet Filter）是Linux内核提供的一种强大的动态追踪和过滤技术，它可以使用户空间程序在不修改内核代码的情况下，对内核执行的系统调用、网络数据包等进行监控和处理。近年来，eBPF已经成为了Linux系统中优化性能和安全的重要工具之一。

​		本题目旨在探索使用eBPF技术优化FUSE文件系统的read性能，并在某一个场景下验证，例如大量小文件拷贝场景等，可与社区导师商榷后确定。

### 项目策略框架：

![1](photo/1.png)

**框架实现过程描述：**

(1)当用户空间应用程序发出lookup命令后，经过系统调用传递至VFS层；

(2)VFS层将请求识别并下发至FUSE驱动层；

(3’)FUSE驱动会首先前往BPF VM空间中进行查询；

(4’)在BPF VM空间中有真正存储元数据的BPF Map结构，内核会对该结构中的元数据进行查询。如果查询到目标元数据，则进入(7)，否则，返回(3’)；

(3)如果在BPF Map中查询失败后，将经过(3’)返回到FUSE驱动层，接下来FUSE驱动会将请求通过内核—用户之间的通信通道传递给FUSE Daemon；

(4)经过FUSE Daemon一般用户请求处理并筛选出其中的I/O请求之后，通过系统调用将其传递给VFS层；

(5)接下来，VFS层将I/O请求转发至下层的文件系统；

(6)最后，右下层的文件系统实现对磁盘数据的真正的I/O操作，并将其返回给用户空间应用程序；

(7)如果在(4’)中查询到了目标元数据，则直接通过BPF映射结构以及相应的BPF Handlers(对BPF Map操作的函数)将其给与FUSE Daemon，FUSE Daemon会将目标元数据返回给用户空间的应用程序。

(0‘)这一步是由于原本在BPF Map中未查询到目标数据，前往磁盘中取得目标数据之后，通过BPF Handlers将目标数据存放至BPF Map结构之中。虽然这一步不属于ExtFUSE框架的工作流程，但这一步为下一次用户空间获取文件数据的优化做出了贡献。

### 项目框架复现：

请查看https://github.com/13186379707/boke/blob/main/eBPF_FUSE/eBPF_FUSE_read/docs/framework%20reproduction/extfuse%20framework.pdf文件。
