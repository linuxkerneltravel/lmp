#include "../include/lib.h"
#include "../include/percpu.h"

struct lock_entry __percpu *percpu_lock_entry;

/* 分配per_cpu变量percpu_lock_entry,并赋初值 */
extern int alloc_percpu_lock_entry(void)
{
    unsigned int cpu;
    struct lock_entry *lock_entry;

    percpu_lock_entry = alloc_percpu(struct lock_entry);
    if (!percpu_lock_entry)
    {
        printk(KERN_ERR "Failed alloc_percpu lock_entry!\n");
        return -1;
    }

    for_each_online_cpu(cpu)
    {
        lock_entry = per_cpu_ptr(percpu_lock_entry, cpu);
        lock_entry->start_time = 0;
    }
    return 0;
}

/* 销毁per_cpu变量percpu_lock_entry */
extern void free_percpu_lock_entry(void)
{
    free_percpu(percpu_lock_entry);
}

MODULE_LICENSE("GPL");
