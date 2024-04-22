#include "../include/lib.h"
#include "../include/proc.h"
#include "../include/kprobe.h"
#include "../include/data.h"
#include "../include/xarray.h"
#include "../include/kthread.h"
#include "../include/kfifo.h"

struct task_struct *datasave_task;

static int __kprobes datasave_handler(void *data)
{
    int err;
    unsigned int len;
    unsigned long pid, cpu, key, index;
    struct kp_info *kp_info;
    struct task_info *task_info, *task_info_alloc = NULL;

    while (!kthread_should_stop())
    {
        spin_lock_irq(&kfifo_lock);
        len = kfifo_out(&kfifo, &kp_info, sizeof(struct kp_info *));
        spin_unlock_irq(&kfifo_lock);

        if (!len)
            msleep(10);
        else
        {
            if (atomic_cmpxchg(&(kp_info->kp_state), KP_STATE_WAITING, KP_STATE_READING) & KP_STATE_WAITING)
            {
                key = pid = kp_info->task->pid;
                cpu = kp_info->cpu;
                if (!pid)
                    key = (cpu << 32) | pid;

                task_info = xa_load(xa, key);
                if (task_info == NULL)
                {
                    task_info_alloc = kmalloc(sizeof(*task_info_alloc), GFP_KERNEL);
                    init_task_info(task_info_alloc, kp_info);

                    err = xa_err(xa_store(xa, key, task_info_alloc, GFP_KERNEL));
                    if (err)
                        goto remove_read;
                    task_info = task_info_alloc;
                }

                update_task_info(task_info, kp_info);

            remove_read:
                refcount_dec(&(kp_info->task->usage));
                atomic_set(&(kp_info->kp_state), 0);
            }
        }
    }
    return 0;
}

extern void datasave_task_init(void)
{
    datasave_task = kthread_run(datasave_handler, NULL, "datasave-%s", "irq_mod");
    if (DEBUG)
        printk(KERN_INFO "INIT alloc_task_datasave\n");
}

extern void datasave_task_exit(void)
{
    int res;
    if(datasave_task!=NULL)
    {
        res = kthread_stop(datasave_task);
        if (DEBUG)
            printk(KERN_INFO "Exit datasave_task,res:%d\n",res);
    }
    else
    {
        if (DEBUG)
            printk(KERN_INFO "datasave_task pointer is NULL\n");
    }
       

}

MODULE_LICENSE("GPL");
