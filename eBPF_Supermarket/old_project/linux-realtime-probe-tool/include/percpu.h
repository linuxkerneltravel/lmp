#ifndef PERCPU_H
#define PERCPU_H

#include "lib.h"
#include "kprobe.h"

/* per_cpu变量lock_entry,记录关闭local中断的起始时间 */
struct lock_entry {
    unsigned long       start_time;
};

extern struct lock_entry __percpu *percpu_lock_entry;

extern int alloc_percpu_lock_entry(void);
extern void free_percpu_lock_entry(void);

#endif
