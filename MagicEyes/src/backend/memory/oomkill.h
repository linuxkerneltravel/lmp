//
// Created by fzy on 24-2-1.
//

#ifndef MAGICEYES_OOMKILL_H
#define MAGICEYES_OOMKILL_H

#if 0
#include <linux/oom.h>
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long
#define TASK_COMM_LEN 16

struct data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};
#endif

#define TASK_COMM_LEN 16

struct data_t {
    __u32 fpid;
    __u32 tpid;
    __u64 pages;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};

#endif //MAGICEYES_OOMKILL_H
