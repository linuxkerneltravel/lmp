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

2.挂载点及挂载原因

挂载点：finish_task_switch

挂载原因：

首先，获取进程级别内存使用信息首先需要获取到进程的task_struct结构体，其中在mm_struct成员中存在一个保存进程当前内存使用状态的数组结构，因此有关进程的大部分内存使用信息都可以通过这个数组获得。其次，需要注意函数的插入点，插入点的选取关系到数据准确性是否得到保证，而在进程的内存申请，释放，规整等代码路径上都存在页面状态改变，但是数量信息还没有更新的相关结构中的情况，如果插入点这两者中间，数据就会和实际情况存在差异，所有在确保可以获取到进程PCB的前提下，选择在进程调度代码路径上考虑。而finish_task_switch函数是新一个进程第一个执行的函数，做的事却是给上一个被调度出去的进程做收尾工作，所有这个函数的参数是上一个进程的PCB，从这块获得上一个进程的内存信息就可以确保在它没有再次被调度上CPU执行的这段时间内的内存数据稳定性。因此最后选择将程序挂载到finish_task_switch函数上。以下是调度程序处理过程：

![](./image/6.png)

数据来源有两部分，一个是mm_struc结构本身存在的状态信息，另一个是在mm_rss_stat结构中，它总共统计四部分信息，内核定义如下：

![](./image/7.png)

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

■ 打印出来的内存申请标志与申请内存传递进去的标志不符，分析原因可能内核在进行alloc_pages函数之前有对标志位进行处理。

■ 因为内存管理区的剩余内存空间处在vm_stat数组第一位，经过分析，使用指针提取的数组第一个数据总是存在差异，需要调整。

■ 对打印的标志位需要进一步解析，方便快速确认当前申请页面类型。

3.挂载点及原因

挂载点：get_page_from_freelist

原因:

经过对内核源码的分析，页面申请失败分析工具的理想挂载点应该是慢速路径的入口函数（__alloc_pages_slowpath）。但是这个函数不允许ebpf程序挂载，而且这个函数内部也不存在合理的挂载点，所有将函数挂载点选在快速路径的入口函数get_page_from_freelist上。因为页面申请的控制结构体ac在这两个函数之间不存在信息更改，所以可以确保这两个函数传递的ac结构体是相同的，不会对提取出来的数据产生影响。为了确保数据确实是在页面申请失败的情况下才会打印数据，需要对alloc_pages_nodemask函数的返回值进行挂载，当alloc_pages_nodemask函数没有返回页面结构体page时，也就是页面申请失败的情况下单元提取的数据。

### pr

1.采集信息

| 参数          | 含义                                         |
| ------------- | -------------------------------------------- |
| reclaim       | 要回收的页面数量                             |
| reclaimed     | 已经回收的页面数量                           |
| unqueue_dirty | 还没开始回写和还没在队列等待的脏页           |
| congested     | 正在块设备上回写的页面，含写入交换空间的页面 |
| writeback     | 正在回写的页面                               |

2.挂载点与挂载原因

挂载点

shrink_page_list

挂载原因

shrink_page_list函数是页面回收后期指向函数，主要操作是遍历链表中每一个页面，根据页面的属性确定将页面添加到回收队列、活跃链表还是不活跃链表.这块遍历的链表是在上一级函数 shrink_inactive_list中定义的临时链表，因为一次最多扫描32个页面，所有链表最多含有32个页面。在shrink_page_list这个函数中还有一个重要操作是统计不同状态的页面数量并保存在scan_control结构体中。而工具数据提取的位置就是找到这个结构体并获取有关性能指标。因为这个提取的数据都是内核函数实时更改的，所有具有较高准确性。

scan_control结构体是每次进行内存回收时都会被回收进程重新定义，所有会看到数据是一个增长状态，之后有回归0，这和挂载点也有一定关系。

------

## 测试环境

deepin20.6，Linux-5.17；

libbpf：[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)

