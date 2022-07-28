# 内存子系统

------

## 背景意义

内存子系统是Linux内核中是一个相对复杂的模块，内核中几乎所有的数据、缓存、程序指令都有内存模块参与管理。在内存不足的情况下，这些数据就会被存储在磁盘的交换空间中，但是磁盘的处理速度相对与内存非常慢，当内存和磁盘频繁进行数据交换时，缓慢的磁盘读写速度非常影响系统性能。系统可能因内存不足从而终止那些占用内存较大的进程，导致程序运行故障。因此准确的监控分析内存性能状况就变得非常重要。

目前，传统的内存性能分析工具通过读取proc文件系统下的数据，经过简单的处理后呈现给用户，方便管理人员随时了解系统状况。然而这些工具的灵活性非常差，单个工具输出的信息有限。系统维护人员在分析性能问题时常常需要借助多个工具才能进行。步骤繁琐且工具本身对系统性能也有一定影响。随着ebpf技术在系统可观测上的发展，利于ebpf非侵入式的数据获取方式已被大多数企业、高校认可并取得了一定的研究成果。ebpf的可编程性可以让管理人员灵活的获取系统的运行数据，而且在数据的提取粒度上有着传统工具无法比拟的优势。现在，ebpf作为Linux内核顶级子系统，已经成为实现Linux内核可观测性、网络和内核安全的理想技术。



------

## 项目介绍

本项目是内存性能分析工具集合，采用libbpf编写。现有工具procstat（进程内存状态报告），sysstat（系统内存状态报告）。计划随后添加页面申请失败的相关分析工具。为了提高工具的适用范围，在编写时已经尽可能的细粒度展示有关数据信息。由于数据信息量过大，计划之后会将信息按照不同模块分类，并提供选项参数。

### procstat

1.采集信息：

| 参数     | 含义                     |
| -------- | ------------------------ |
| vsize    | 进程使用的虚拟内存       |
| size     | 进程使用的最大物理内存   |
| rssanon  | 进程使用的匿名页面       |
| rssfile  | 进程使用的文件映射页面   |
| rssshmem | 进程使用的共享内存页面   |
| vswap    | 进程使用的交换分区大小   |
| vdata    | 进程使用的私有数据段大小 |
| vpte     | 进程页表大小             |
| vstk     | 进程用户栈大小           |

2.存在问题



3.挂载点及挂载原因



### sysstat

1.采集信息：

| 参数           | 含义                             |
| -------------- | -------------------------------- |
| active         | LRU活跃内存大小                  |
| inactive       | LRU不活跃内存大小                |
| anon_active    | 活跃匿名内存大小                 |
| anon_inactive  | 不活跃匿名内存大小               |
| file_active    | 活跃文件映射内存大小             |
| file_inactive  | 不活跃文件映射内存大小           |
| unevictable    | 不可回收内存大小                 |
| dirty          | 脏页大小                         |
| writeback      | 正在回写的内存大小               |
| anonpages      | RMAP页面                         |
| mapped         | 所有映射到用户地址空间的内存大小 |
| shmem          | 共享内存                         |
| kreclaimable   | 内核可回收内存                   |
| slab           | 用于slab的内存大小               |
| sreclaimable   | 可回收slab内存                   |
| sunreclaim     | 不可回收slab内存                 |
| NFS_unstable   | NFS中还没写到磁盘中的内存        |
| writebacktmp   | 回写所使用的临时缓存大小         |
| anonhugepages  | 透明巨页大小                     |
| shmemhugepages | shmem或tmpfs使用的透明巨页       |

2.存在问题

■ 部分性能数据存在于内核全局变量中，而这些数据不会作为函数参数存储在栈中，因此这些数据目前还没实现统计

■ 因为内核对内存管理不会是物理内存的全部容量，而且最大管理内存的数据结构是内存结点，所以以上统计数据是以当前内存结点实际管理的内存容量为基准。

■ 当前剩余内存总量的统计需要遍历所有内存管理区来统计，但是由于内存管理区的空闲页面信息存储在数组第一个位置，使用指针指向时，统计到的数据不准确，使用变量统计会出现数据类型错误的报告。

3.挂载点及挂载原因

挂载点：get_page_from_freelist

原因：

首先，内存状态数据的提取需要获取到内存节点pglist_data数据结构，这个结构是对内存的总体抽象。pglist_data数据结构末尾有个vm_stat的数组，里面包含了当前内存节点所有的状态信息。所有只需要获取到pglist_data结构就能拿到当前的内存状态信息。但是物理内存分配在选择内存节点是通过mempolicy结构获取，无法获得具体的节点结构。选择内存节点的函数处理流程如下：

```c
struct mempolicy *get_task_policy(struct task_struct *p)
{
        struct mempolicy *pol = p->mempolicy;//根据当前task_struct取得
        int node;

        if (pol)
                return pol; 

        node = numa_node_id();
        if (node != NUMA_NO_NODE) {//存在其他节点
                pol = &preferred_node_policy[node];
                /* preferred_node_policy is not initialised early in boot */
                if (pol->mode)
                        return pol; 
        }    

        return &default_policy;//不存在其他节点返回本地节点
}
```

经过对内存申请的内部结构alloc_context分析(这是内存申请过程中临时保存相关参数的结构)，当前内存节点是可以通过：alloc_context——>zoneref——>zone——>pglist_data的路径访问到。

其次，因为函数执行申请内存的过程对获取内存节点数据的影响不大，所以只要可以获得alloc_context数据结构，在整个申请路径上挂载函数都是可以的。sysstat工具选择的挂载点是get_page_from_freelist函数。这个函数是快速物理内存分配的入口函数。因为内核在进行物理内存分配时，都会进入快速路径分配，只有当失败时才会进入慢速路径，所以get_page_from_freelist函数是必经函数。整个处理过程以及函数关系如下：

![](./image/1.png)

但是，经过对proc文件系统的打印函数meminfo_proc_show函数的分析得知，影响内存性能的参数在vm_stat中无法全部获得。一部分数据需要遍历当前内存节点包含的所有内存管理区zone结构中vm_stat数组获得，一部分需要读取全局变量vm_node_stat获得。但是内核的全局变量不会作为函数参数参与数据处理，目前还没具体方法获得这部分数据。

### paf

1.采集信息

| 参数    | 含义                                 |
| ------- | ------------------------------------ |
| min     | 内存管理区处于最低警戒水位的页面数量 |
| low     | 内存管理区处于低水位的页面数量       |
| high    | 内存管理区处于高水位的页面数量       |
| present | 内存管理区实际管理的页面数量         |
| flag    | 申请页面时的权限（标志）             |

内存申请失败一般集中在申请权限不够或者是权限冲突导致，申请权限不够是当内核申请优先级较低的页面时，虽然内存管理区有足够的页面满足这次申请数量，但是当前剩余空闲页面少于最低警戒水位，因此导致内核无法成功分配页面的情况。权限冲突，例如内核在开启CMA机制下导致的页面页面申请失败的情况，这种情况下管理区空闲页面需要减去CMA机制占用内存才是当前可分配内存。相关权限判断代码如下：

添加CMA权限代码路径mm/page_alloc.c

```c
static inline unsigned int
gfp_to_alloc_flags(gfp_t gfp_mask)
{
	unsigned int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;
    ...
	alloc_flags |= (__force int) (gfp_mask & __GFP_HIGH);
    ...
	if (gfp_mask & __GFP_KSWAPD_RECLAIM)
			alloc_flags |= ALLOC_KSWAPD;
    
#ifdef CONFIG_CMA
	if (gfpflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
			alloc_flags |= ALLOC_CMA;
#endif
	return alloc_flags;
}
```

CMA机制内存处理代码:

```c
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
                         int classzone_idx, unsigned int alloc_flags, long free_pages)
{
   ...
#ifdef CONFIG_CMA
        if (!(alloc_flags & ALLOC_CMA))
                free_pages -= zone_page_state(z, NR_FREE_CMA_PAGES);
#endif  
  
        if (free_pages <= min + z->lowmem_reserve[classzone_idx])
                return false;
	...
#ifdef CONFIG_CMA
       if ((alloc_flags & ALLOC_CMA) &&
                !list_empty(&area->free_list[MIGRATE_CMA])) {
                        return true;
                }
#endif
}  
```

2.存在问题



3.挂载点及原因



------

## 测试环境

deepin20.6，Linux-5.17；

libbpf：[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)

------

## 维护

乔哲-西安邮电大学陈莉君研究生团队

邮箱：qiaozhe1@outlook.com
