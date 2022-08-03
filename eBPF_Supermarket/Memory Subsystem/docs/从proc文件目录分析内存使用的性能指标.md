# 从proc目录分析内存使用的性能指标

proc目录是一个位于内存中的伪文件系统。该目录保存这系统所有的运行数据，例如系统内存、磁盘io、cPU和系统配置等。同时，proc目录也是一个系统控制入口，用户可以通过更改其中某些文件数据来改变内核的运行状态。在proc目录下，对于系统级内存指标都在meminfo文件下，这个文件中包含了当前系统内存状态的大部分信息。以下列举了常见的一些指标：

| 参数            | 含义                                           | 参数           | 含义                                                 |
| --------------- | ---------------------------------------------- | -------------- | ---------------------------------------------------- |
| memtotal        | 系统当前可用内存总量                           | memavailable   | 系统当前可使用的页面，包含空闲，文件映射，可回收页面 |
| swaptotal       | 交换分区大小                                   | swapfree       | 交换分区的空闲页面大小                               |
| cached          | 用于页面高速缓存的页面                         | unevictable    | 不能回收的页面                                       |
| active          | 活跃的匿名页，包含匿名页和文件页               | inactive       | 不活跃的匿名页，包含匿名页面和文件页面               |
| dirty           | 脏页大小。由文件脏页统计                       | writeback      | 正在会写的脏页数量，                                 |
| anonpages       | 有反向映射的页面，通常是匿名页面映射到用户空间 | mapped         | 所有映射到用户地址空间的文件缓存页面                 |
| shmem           | 共享内存                                       | kreclaimable   | 内核可以回收的页面                                   |
| slab            | 所有用于slab分配器的页面                       | sreclaimable   | 可回收的slab页面                                     |
| sunreclaim      | 不可回收的slab页面                             | NFS_unstable   | 发送到服务器但是还没有写入磁盘的页面                 |
| writebacktmp    | 回写过程中使用的临时缓存                       | percpu         | percpu机制使用的页面                                 |
| hugepages_total | 普通巨页数量                                   | hugepages_free | 空闲的巨页数量                                       |

对于进程的内存信息都保存在、proc/进程号/status中，在这个文件下保存这有关进程的所有参数信息，内存信息只是其中一部分：

| 参数        | 含义                   | 参数     | 含义                   |
| ----------- | ---------------------- | -------- | ---------------------- |
| vmpeak      | 进程使用的最大虚拟内存 | vmsize   | 进程使用的虚拟内存     |
| vmlack      | 进程锁住的内存         | vmpin    | 进程固定的内存         |
| vmhwm       | 进程使用的最大物理内存 | rssanon  | 进程使用的匿名页面     |
| rssfile     | 进程使用的文件映射页面 | rssshmem | 进程使用的共享页面     |
| vmdata      | 进程私有数据段大小     | vmstk    | 进程用户栈大小         |
| vmexe       | 进程代码段大小         | vmlib    | 进程共享库大小         |
| vmpte       | 进程页表大小           | vmswap   | 进程使用的交换空间大小 |
| hugetlbpage | 进程使用的巨页大小     |          |                        |



## 1. 从内核角度分析proc目录下内存指标来源

核在处理内存状态信息时不会在需要时才会遍历整个内存节点，这样只会消耗大量硬件资源。而是在内存页面状态发生改变时调用内核提供的接口函数进行计算并保存在对应的全局数组中。Linux内核总共定义了三个全局数组，分别是vm_node_stat（内存节点有关统计数据）、vm_zone_stat（内存管理区有关统计数据）、vm_numa_stat（numa相关统计数据），对应在mm/vmstat.c文件中。如下：

```c
/*
 * Manage combined zone based / global counters
 *
 * vm_stat contains the global counters
 */
atomic_long_t vm_zone_stat[NR_VM_ZONE_STAT_ITEMS] __cacheline_aligned_in_smp;
atomic_long_t vm_numa_stat[NR_VM_NUMA_STAT_ITEMS] __cacheline_aligned_in_smp;
atomic_long_t vm_node_stat[NR_VM_NODE_STAT_ITEMS] __cacheline_aligned_in_smp;
EXPORT_SYMBOL(vm_zone_stat);
EXPORT_SYMBOL(vm_numa_stat);
EXPORT_SYMBOL(vm_node_stat);

#ifdef CONFIG_SMP
```

内核总共提供了4个接口函数操作这些全局数组，包含获取数据、增加/递减数据。

```c
/*增加页面数量到内存管理区vm_stat数组和全局vm_zone_stat数组中*/
static inline void zone_page_state_add(long x, struct zone *zone,
                                 enum zone_stat_item item)
{
        atomic_long_add(x, &zone->vm_stat[item]);
        atomic_long_add(x, &vm_zone_stat[item]);
}
/*增加页面数量到内存节点vm_stat数组和全局vm_node_stat数组中*/
static inline void node_page_state_add(long x, struct pglist_data *pgdat,
                                 enum node_stat_item item)
{
        atomic_long_add(x, &pgdat->vm_stat[item]);
        atomic_long_add(x, &vm_node_stat[item]);
}
/*读取全局vm_zone_stat数组中统计数据*/
static inline unsigned long global_zone_page_state(enum zone_stat_item item)
{
        long x = atomic_long_read(&vm_zone_stat[item]);
#ifdef CONFIG_SMP
        if (x < 0)
                x = 0;
#endif
        return x;
}
/*读取全局vm_node_stat数组中统计数据*/
static inline unsigned long global_node_page_state(enum node_stat_item item)
{
        long x = atomic_long_read(&vm_node_stat[item]);
#ifdef CONFIG_SMP
        if (x < 0)
                x = 0;
#endif
        return x;
}
```

同时在pglist_data和zone数据结构中定义了vm_stat数组辅助统计状态信息。而proc目录下和内存有关的数据大部分都会通过三个全局变量和vm_stat获取。剩余数据则通过遍历全部zone数据结构中vm_stat数组成员或者其他独立的全局变量读取。这些单独全局变量的读取函数为atomic_long_read。

对应到meminfo文件中的数据，由内核中的meminfo_proc_show函数打印，这个函数实现在fs/proc/meminfo.c中。函数的实现思路非常简单，就是直接调用有关数组操作函数读取对应的全局变量信息，经过简单计数之后直接打印。具体实现如下：

```c
static int meminfo_proc_show(struct seq_file *m, void *v)
{
		...
        /*调用函数获取全局变量信息*/    
        si_meminfo(&i);
        si_swapinfo(&i);
        committed = percpu_counter_read_positive(&vm_committed_as);

        cached = global_node_page_state(NR_FILE_PAGES) -
                        total_swapcache_pages() - i.bufferram;
        if (cached < 0)
                cached = 0;

        for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
                pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

        available = si_mem_available();
        sreclaimable = global_node_page_state(NR_SLAB_RECLAIMABLE);
        sunreclaim = global_node_page_state(NR_SLAB_UNRECLAIMABLE);
    	/*数据输出*/
		show_val_kb(m, "MemTotal:       ", i.totalram);
    	...
    	show_val_kb(m, "Percpu:         ", pcpu_nr_pages());

        hugetlb_report_meminfo(m);
        arch_report_meminfo(m);
        return 0;
}
```

进程级别的内存状态信息保存在task_struct的mm_struct成员中，其中物理内存的使用情况保存在mm_rss_stat数据结构中,在include/linux/mm_types_task.h 中定义如下:

```c
struct mm_rss_stat {
        atomic_long_t count[NR_MM_COUNTERS];
};

enum {  
        MM_FILEPAGES,   /* 进程使用的文件映射页面数量 */
        MM_ANONPAGES,   /* 进程使用的匿名页面数量 */
        MM_SWAPENTS,    /* 进程使用的交换分区匿名页面数量 */
        MM_SHMEMPAGES,  /* 进程共享的内存页面数量 */
        NR_MM_COUNTERS
};
```

同时内核也为这些数据定义了相关接口函数，这些接口定义在include/linux/mm.h中

```c
/*获取member计数*/
static inline unsigned long get_mm_counter(struct mm_struct *mm, int member)
{       
        long val = atomic_long_read(&mm->rss_stat.count[member]);

#ifdef SPLIT_RSS_COUNTING
        if (val < 0)
                val = 0;
#endif  
        return (unsigned long)val;
}
/*增加value个member计数*/
static inline void add_mm_counter(struct mm_struct *mm, int member, long value)
{
        atomic_long_add(value, &mm->rss_stat.count[member]);
}
/*使member计数加1*/
static inline void inc_mm_counter(struct mm_struct *mm, int member)
{
        atomic_long_inc(&mm->rss_stat.count[member]);
}
/*使member计数减1*/
static inline void dec_mm_counter(struct mm_struct *mm, int member)
{
        atomic_long_dec(&mm->rss_stat.count[member]);
}
```

在proc/j进程号/status文件中，对于进程内存的使用数据都是通过以上的方式采集。具体的实现在

```c
void task_mem(struct seq_file *m, struct mm_struct *mm)
{
		...
        /*调用接口函数读取mm_struct数据结构中的数据*/    
        anon = get_mm_counter(mm, MM_ANONPAGES);
        file = get_mm_counter(mm, MM_FILEPAGES);
        shmem = get_mm_counter(mm, MM_SHMEMPAGES);

        hiwater_vm = total_vm = mm->total_vm;
        if (hiwater_vm < mm->hiwater_vm)
                hiwater_vm = mm->hiwater_vm;
        hiwater_rss = total_rss = anon + file + shmem;
        if (hiwater_rss < mm->hiwater_rss)
                hiwater_rss = mm->hiwater_rss;

        text = PAGE_ALIGN(mm->end_code) - (mm->start_code & PAGE_MASK);
        text = min(text, mm->exec_vm << PAGE_SHIFT);
        lib = (mm->exec_vm << PAGE_SHIFT) - text;

        swap = get_mm_counter(mm, MM_SWAPENTS);
    	/*将数据输出到status文件中*/
        SEQ_PUT_DEC("VmPeak:\t", hiwater_vm);
        ...
        SEQ_PUT_DEC(" kB\nVmSwap:\t", swap);
        seq_puts(m, " kB\n");
        hugetlb_report_usage(m, mm);
}
```

## 2. 传统工具数据来源与信息解读



## 3. 对以上信息的借鉴