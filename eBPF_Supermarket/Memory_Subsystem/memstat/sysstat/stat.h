#ifndef __STAT_H
#define __STAT_H

struct event {
/*lru*/
        int pid;
        unsigned long present;
        unsigned long anon_inactive;//0
        unsigned long anon_active;//1
        unsigned long file_inactive;//2
        unsigned long file_active;//3
        unsigned long unevictable;//不可回收页面        

        unsigned long slab_reclaimable;//kehuishou
        unsigned long slab_unreclaimable;//bukehuishou

        unsigned long anon_isolated;        //匿名隔离页面
        unsigned long file_isolated;        //文件隔离页面
//gongzuoji
        unsigned long working_nodes;//12
        unsigned long working_refault;
        unsigned long working_activate;
        unsigned long working_restore;
        unsigned long working_nodereclaim;

        unsigned long anon_mapped;//17
        unsigned long file_mapped;

        unsigned long file_pages;//19
        unsigned long file_dirty;
        unsigned long writeback;
        unsigned long writeback_temp;

        unsigned long shmem;//共享内存23
       unsigned long shmem_thps;
        unsigned long pmdmapped;
        unsigned long anon_thps;
        unsigned long unstable_nfs;
        unsigned long vmscan_write;
        unsigned long vmscan_immediate;

        unsigned long diried;
        unsigned long written;
        unsigned long kernel_misc_reclaimable;

        unsigned long vsize;

};
#endif
