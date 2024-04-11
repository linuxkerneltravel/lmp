#ifndef __MEM_WATCHER_H
#define __MEM_WATCHER_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define ___GFP_DMA              0x01u
#define ___GFP_HIGHMEM          0x02u
#define ___GFP_DMA32            0x04u
#define ___GFP_MOVABLE          0x08u
#define ___GFP_RECLAIMABLE      0x10u
#define ___GFP_HIGH             0x20u
#define ___GFP_IO               0x40u
#define ___GFP_FS               0x80u
#define ___GFP_WRITE            0x100u
#define ___GFP_NOWARN           0x200u
#define ___GFP_RETRY_MAYFAIL    0x400u
#define ___GFP_NOFAIL           0x800u
#define ___GFP_NORETRY          0x1000u
#define ___GFP_MEMALLOC         0x2000u
#define ___GFP_COMP             0x4000u
#define ___GFP_ZERO             0x8000u
#define ___GFP_NOMEMALLOC       0x10000u
#define ___GFP_HARDWALL         0x20000u
#define ___GFP_THISNODE         0x40000u
#define ___GFP_ATOMIC           0x80000u
#define ___GFP_ACCOUNT          0x100000u
#define ___GFP_DIRECT_RECLAIM   0x200000u
#define ___GFP_KSWAPD_RECLAIM   0x400000u
	
#define GFP_ATOMIC      (__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL      (__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_NOWAIT      (__GFP_KSWAPD_RECLAIM)
#define GFP_NOIO        (__GFP_RECLAIM)
#define GFP_NOFS        (__GFP_RECLAIM | __GFP_IO)
#define GFP_USER        (__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_DMA         __GFP_DMA
#define GFP_DMA32       __GFP_DMA32
#define GFP_HIGHUSER    (GFP_USER | __GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE    (GFP_HIGHUSER | __GFP_MOVABLE)
#define GFP_TRANSHUGE_LIGHT     ((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
                         __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
#define GFP_TRANSHUGE   (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)

struct paf_event {
	unsigned long min;
	unsigned long low;
	unsigned long high;
	unsigned long present;
	unsigned long protection;
	int flag;
};

struct pr_event {
	unsigned long reclaim;
	unsigned long reclaimed;
	unsigned int unqueued_dirty;
	unsigned int congested;
	unsigned int writeback;
};

struct procstat_event {
	/*进程内存状态报告*/
	pid_t pid;
	long nvcsw;
	long nivcsw;
	long vsize;              //虚拟内存
	long size;               //物理内存
	long long rssanon;       //匿名页面
	long long rssfile;       //文件页面
	long long rssshmem;      //共享页面
	long long vswap;         //交换页面
	long long Hpages;        //hugetlbPages
	long Vdata;              //Private data segments
	long Vstk;               //User stack
	long long VPTE;
};

struct sysstat_event {
	/*系统内存状态报告*/
	unsigned long present;
	unsigned long anon_inactive; // 0
	unsigned long anon_active;	 // 1
	unsigned long file_inactive; // 2
	unsigned long file_active;	 // 3
	unsigned long unevictable;	 // 不可回收页面
	unsigned long slab_reclaimable;
	unsigned long slab_unreclaimable;
	unsigned long anon_isolated; // 匿名隔离页面
	unsigned long file_isolated; // 文件隔离页面

	unsigned long working_nodes; // 12
	unsigned long working_refault;
	unsigned long working_activate;
	unsigned long working_restore;
	unsigned long working_nodereclaim;

	unsigned long anon_mapped; // 17
	unsigned long file_mapped;

	unsigned long file_pages; // 19
	unsigned long file_dirty;
	unsigned long writeback;
	unsigned long writeback_temp;

	unsigned long shmem; // 共享内存23
	unsigned long shmem_thps;
	unsigned long pmdmapped;
	unsigned long anon_thps;
	unsigned long unstable_nfs;
	unsigned long vmscan_write;
	unsigned long vmscan_immediate;

	unsigned long diried;
	unsigned long written;
	unsigned long kernel_misc_reclaimable;
};

/*memleak.h*/
#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240
 
struct alloc_info {
    __u64 size;
    int stack_id;
};

union combined_alloc_info {
    struct {
        __u64 total_size : 40;
        __u64 number_of_allocs : 24;
    };
    __u64 bits;
};

#endif /* __MEM_WATCHER_H */