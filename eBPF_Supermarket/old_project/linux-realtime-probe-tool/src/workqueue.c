#include "../include/lib.h"
#include "../include/proc.h"
#include "../include/kprobe.h"
#include "../include/data.h"
#include "../include/xarray.h"
#include "../include/workqueue.h"
#include "../include/kfifo.h"

struct workqueue_struct  *wq;
struct work_struct       work;

void work_handler(struct work_struct *work)
{
    unsigned long pid, cpu, key, index;
    struct kp_info *kp_info;
    struct task_info *task_info;

    while (getNodeParm(enable) && kfifo_out(&kfifo, &kp_info, sizeof(struct kp_info *))) {
        
        if (atomic_cmpxchg(&(kp_info->kp_state),
                KP_STATE_WAITING, KP_STATE_READING) & KP_STATE_WAITING) {
            key = pid = kp_info->task->pid;
            cpu = kp_info->cpu;

             if(DEBUG) printk("workqueue: pid->%lu cpu->%lu\n", key, cpu);

            if (!pid)
                key = (cpu << 32) | pid;
            
            xa_lock(xa);
            task_info = xa_load(xa, key);
            if (!task_info) {
                task_info = kmalloc(sizeof(*task_info), GFP_KERNEL);
                init_task_info(task_info, kp_info);
                xa_store(xa, key, task_info, GFP_KERNEL);
            }
            xa_unlock(xa);

            update_task_info(task_info, kp_info);

            refcount_dec(&(kp_info->task->usage));
            atomic_set(&(kp_info->kp_state), 0);
        }
    }

    if (!getNodeParm(enable)) {
        xa_lock(xa);
        xa_for_each(xa, index, task_info) {
            free_task_info(task_info);
        }
        xa_unlock(xa);

        destroy_xarray();
    }
}

extern int wq_init(void)
{
    wq = create_singlethread_workqueue("handler_fifo");
    if(DEBUG) printk("alloc_wq!\n");

    INIT_WORK(&work, work_handler);

    return 0;
}

extern void wq_exit(void)
{
    if(DEBUG) printk("Workqueue is exit!\n");
    destroy_workqueue(wq);
}

MODULE_LICENSE("GPL");