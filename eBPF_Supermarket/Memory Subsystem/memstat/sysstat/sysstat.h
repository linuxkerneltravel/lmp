/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
/*系统内存状态报告*/
    	unsigned long present;
	unsigned long anon_inactive;//0
	unsigned long anon_active;//1
        unsigned long file_inactive;//2
	unsigned long file_active;//3
	unsigned long unevictable;//不可回收页面	
	unsigned long slab_reclaimable;
	unsigned long slab_unreclaimable;
	unsigned long anon_isolated;        //匿名隔离页面
	unsigned long file_isolated;        //文件隔离页面

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

};



#endif /* __BOOTSTRAP_H */
