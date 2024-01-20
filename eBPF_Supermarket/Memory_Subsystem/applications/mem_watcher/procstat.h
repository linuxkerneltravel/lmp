/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __PROCSTAT_H
#define __PROCSTAT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

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



#endif /* __PROCSTAT_H */
