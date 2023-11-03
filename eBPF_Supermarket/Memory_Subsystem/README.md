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
4.对代码进行注释分析

- paf.bpf.c
```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

// 包含必要的头文件
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "paf.h"

// 定义一个BPF映射，类型为BPF_MAP_TYPE_RINGBUF，最大条目数为1
#define SEC(NAME) __attribute__((section(NAME), used))
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1);
} rgb SEC(".maps");

// 定义一个kprobe钩子函数，钩住了内核函数get_page_from_freelist
SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac)
{
    struct event *e;
    unsigned long *t, y;
    int a;

    // 在ring buffer中预留一块空间以存储事件数据
    e = bpf_ringbuf_reserve(&rgb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 从alloc_context结构中读取数据
    y = BPF_CORE_READ(ac, preferred_zoneref, zone, watermark_boost);
    t = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark);

    // 填充事件结构体
    e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, present_pages);
    e->min = t[0] + y;
    e->low = t[1] + y;
    e->high = t[2] + y;
    e->flag = (int)gfp_mask;

    // 提交事件到ring buffer中
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```
```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "paf.h"
#include "paf.skel.h"
#include <sys/select.h>

// 存储命令行参数的结构体
static struct env {
    long choose_pid; // 选择的进程ID
    long time_s;     // 延时时间（单位：毫秒）
    long rss;        // 是否显示进程页面信息
} env;

// 命令行选项定义
static const struct argp_option opts[] = {
    { "choose_pid", 'p', "PID", 0, "选择特定进程显示信息。" },
    { "time_s", 't', "MS", 0, "延时打印时间，单位：毫秒" },
    { "Rss", 'r', NULL, 0, "显示进程页面信息。"},
};

// 命令行参数解析函数
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'p':
            env.choose_pid = strtol(arg, NULL, 10);
            break;
        case 't':
            env.time_s = strtol(arg, NULL, 10);
            break;
        case 'r':
            env.rss = true;
            break;
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// 命令行解析器
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
};

// libbpf输出回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

// 信号处理函数，处理Ctrl-C
static volatile bool exiting;
static void sig_handler(int sig) {
    exiting = true;
}

// 毫秒级别的睡眠函数
static void msleep(long ms) {
    struct timeval tval;
    tval.tv_sec = ms / 1000;
    tval.tv_usec = (ms * 1000) % 1000000;
    select(0, NULL, NULL, NULL, &tval);
}

// 处理BPF事件的回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 根据命令行参数选择要显示的信息
    if (env.choose_pid) {
        if (e->pid == env.choose_pid) {
            // 根据是否显示进程页面信息选择输出格式
            if (env.rss) {
                // 显示进程页面信息
                printf("%-8s %-8lu %-8lu %-8lu %-8lu %-8x\n",
                       ts, e->min, e->low, e->high, e->present, e->flag);
            } else {
                // 显示进程内存信息
                printf("%-8s %-8lu %-8lu %-8lu %-8lu\n",
                       ts, e->min, e->low, e->high, e->present);
            }
        }
    } else {
        // 根据是否显示进程页面信息选择输出格式
        if (env.rss) {
            // 显示进程页面信息
            printf("%-8s %-8lu %-8lu %-8lu %-8lu %-8x\n",
                   ts, e->min, e->low, e->high, e->present, e->flag);
        } else {
            // 显示进程内存信息
            printf("%-8s %-8lu %-8lu %-8lu %-8lu\n",
                   ts, e->min, e->low, e->high, e->present);
        }
    }

    // 根据延时时间休眠
    if (env.time_s) {
        msleep(env.time_s);
    } else {
        msleep(1000);
    }
    return 0;
}

// 主函数
int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct paf_bpf *skel;
    int err;

    // 解析命令行参数
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    // 设置libbpf严格模式
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // 设置libbpf错误输出回调函数
    libbpf_set_print(libbpf_print_fn);

    // 设置Ctrl-C的处理函数
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 打开BPF程序
    skel = paf_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 加载BPF程序
    err = paf_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 关联BPF程序和事件
    err = paf_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 创建ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rgb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 打印表头
    if (env.rss) {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "MIN", "LOW", "HIGH", "PRESENT", "FLAG");
    } else {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "MIN", "LOW", "HIGH", "PRESENT");
    }

    // 处理事件
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* 超时时间，单位：毫秒 */);
        // Ctrl-C会产生-EINTR错误
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    // 释放资源
    ring_buffer__free(rb);
    paf_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}

```
5.主要功能
监控系统内存，特别是内存分配方面，输出的信息包括时间戳、进程ID、虚拟内存大小、物理内存等。输出的内容根据用户的选择（特定PID、是否显示RSS等）而变化。除了常规的事件信息外，程序还输出了与内存管理相关的详细信息，主要是present(当前内存中可用的页面数量)，min(在这个阈值下，系统可能会触发内存压缩)，low(在这个阈值下，系统进行内存回收)，high(在这个阈值上，认为内存资源充足)，flag(用于内存分配的状态)。
6.结果展示
![image](https://github.com/linuxkerneltravel/lmp/assets/145275401/68962b13-828d-4c55-88ec-834504ce2d6b)

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

3.对代码进行注释分析
pr.pbf.c
```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

// 包含必要的头文件
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pr.h"

// 定义一个BPF映射，类型为BPF_MAP_TYPE_RINGBUF，最大条目数为1
#define SEC(NAME) __attribute__((section(NAME), used))
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1);
} rgb SEC(".maps");

// 定义一个kprobe钩子函数，钩住了内核函数shrink_page_list
SEC("kprobe/shrink_page_list")
int BPF_KPROBE(shrink_page_list, struct list_head *page_list, struct pglist_data *pgdat, struct scan_control *sc)
{
    struct event *e;
    unsigned long y;
    unsigned int *a;

    // 在ring buffer中预留一块空间以存储事件数据
    e = bpf_ringbuf_reserve(&rgb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 从scan_control结构中读取数据
    e->reclaim = BPF_CORE_READ(sc, nr_to_reclaim); // 需要回收的页面数
    y = BPF_CORE_READ(sc, nr_reclaimed); // 已经回收的页面数
    e->reclaimed = y;

    // 访问未回写的脏页、块设备上回写的页面和正在回写的页面的数量
    a = (unsigned int *)(&y + 1);
    e->unqueued_dirty = *(a + 1);
    e->congested = *(a + 2);
    e->writeback = *(a + 3);

    // 提交事件到ring buffer中
    bpf_ringbuf_submit(e, 0);
    return 0;
}

```
pr.c
```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "pr.h"
#include "pr.skel.h"
#include <sys/select.h>

// 存储命令行参数的结构体
static struct env {
    long choose_pid; // 要选择的进程ID
    long time_s;     // 延时时间（单位：毫秒）
    long rss;        // 是否显示进程页面信息
} env; 

// 命令行选项定义
static const struct argp_option opts[] = {
    { "choose_pid", 'p', "PID", 0, "选择特定进程显示信息。" },
    { "time_s", 't', "MS", 0, "延时打印时间，单位：毫秒" },
    { "Rss", 'r', NULL, 0, "显示进程页面信息。"},
};

// 命令行参数解析函数
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'p':
            env.choose_pid = strtol(arg, NULL, 10);
            break;
        case 't':
            env.time_s = strtol(arg, NULL, 10);
            break;
        case 'r':
            env.rss = true;
            break;
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// 命令行解析器
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
};

// libbpf输出回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

// 信号处理函数，处理Ctrl-C
static volatile bool exiting;
static void sig_handler(int sig) {
    exiting = true;
}

// 毫秒级别的睡眠函数
static void msleep(long ms) {
    struct timeval tval;
    tval.tv_sec = ms / 1000;
    tval.tv_usec = (ms * 1000) % 1000000;
    select(0, NULL, NULL, NULL, &tval);
}

// 处理BPF事件的回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 根据命令行参数选择要显示的信息
    if (env.choose_pid) {
        if (e->pid == env.choose_pid) {
            if (env.rss) {
                // 显示进程页面信息
                printf("%-8s %-8lu %-8lu %-8u %-8u %-8u\n",
                       ts, e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested, e->writeback);
            } else {
                // 显示进程内存信息
                printf("%-8s %-8lu %-8lu %-8lu %-8lu\n",
                       ts, e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested);
            }
        }
    } else {
        if (env.rss) {
            // 显示进程页面信息
            printf("%-8s %-8lu %-8lu %-8u %-8u %-8u\n",
                   ts, e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested, e->writeback);
        } else {
            // 显示进程内存信息
            printf("%-8s %-8lu %-8lu %-8lu %-8lu\n",
                   ts, e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested);
        }
    }

    // 根据延时时间休眠
    if (env.time_s) {
        msleep(env.time_s);
    } else {
        msleep(1000);
    }
    return 0;
}

// 主函数
int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct pr_bpf *skel;
    int err;

    // 解析命令行参数
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    // 设置libbpf严格模式
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // 设置libbpf错误输出回调函数
    libbpf_set_print(libbpf_print_fn);

    // 设置Ctrl-C的处理函数
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 打开BPF程序
    skel = pr_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 加载BPF程序
    err = pr_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 关联BPF程序和事件
    err = pr_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 创建ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rgb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 打印表头
    if (env.rss) {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED", "WRITEBACK");
    } else {
        printf("%-8s %-8s %-8s %-8s %-8s\n", "TIME", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED");
    }

    // 处理事件
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* 超时时间，单位：毫秒 */);
        // Ctrl-C会产生-EINTR错误
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    // 释放资源
    ring_buffer__free(rb);
    pr_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}


```
4.主要功能
跟踪内核中页面的回收行为，记录回收的各个阶段，例如要回收的页面，以回收的页面，等待回收的脏页数，要写回的页数(包括交换空间中的页数)以及当前正在写回的页数。
5.结果展示
![image](https://github.com/linuxkerneltravel/lmp/assets/145275401/c33c6c9b-5f9e-4135-81bc-badee66a6d91)

------

## 测试环境

deepin20.6，Linux-5.17；

libbpf：[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)

