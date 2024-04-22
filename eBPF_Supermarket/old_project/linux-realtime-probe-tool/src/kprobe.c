#include "../include/lib.h"
#include "../include/kfifo.h"
#include "../include/workqueue.h"
#include "../include/kprobe.h"
#include "../include/percpu.h"
#include "../include/objpool.h"
#include "../include/proc.h"

/* handler_lock是上锁时的通用函数 */
static int __kprobes handler_lock(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int cpu;
    unsigned long now;
    struct lock_entry *lock_entry;

    cpu = smp_processor_id();
    now = ktime_get_ns();

    lock_entry = per_cpu_ptr(percpu_lock_entry, cpu);

    lock_entry->start_time = now;

    return 0;
}

/* handler_unlock是解锁时的通用函数 */
static int __kprobes handler_unlock(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int cpu, kp_state;
    unsigned long now, delta;
    struct lock_entry *lock_entry;
    struct task_struct *task;
    struct kp_info *kp_info;

    cpu = smp_processor_id();
    now = ktime_get_ns();

    lock_entry = per_cpu_ptr(percpu_lock_entry, cpu);
    delta = now - lock_entry->start_time;

    if (lock_entry->start_time && (delta >= getNodeParm(threshold)))
    {
        kp_info = new_kp_info(kp_pool); // qq

        if (!(kp_state = atomic_cmpxchg(&(kp_info->kp_state), 0, KP_STATE_WRITING)) ||
            (kp_state = atomic_cmpxchg(&(kp_info->kp_state), KP_STATE_WAITING, KP_STATE_WRITING)) & KP_STATE_WAITING)
        {

            if (kp_state & KP_STATE_WAITING)
                refcount_dec(&(kp_info->task->usage));

            task = (struct task_struct *)current;
            refcount_inc(&(task->usage));

            kp_info->task = task;
            kp_info->lock_addr = regs_get_register(regs, 0);
            kp_info->cpu = cpu;
            kp_info->time_stamp = now;
            kp_info->delta = delta;
            kp_info->num_entries = stack_trace_save((unsigned long *)kp_info->stack_entries,
                                                    NUM_STACK_ENTRIES, 1);

            // atomic_set(&(kp_info->kp_state), KP_STATE_WAITING);

            // printk("pid: %d cpu: %d\n", kp_info->task->pid, kp_info->cpu);

            // 放入kfifo中
            if (spin_trylock(&kfifo_lock))
            {
                if (kfifoPutData(kp_info, sizeof(kp_info))==-1){
                    spin_unlock(&kfifo_lock);
                    refcount_dec(&(task->usage));
                    atomic_set(&(kp_info->kp_state), 0);
                }else{
                    spin_unlock(&kfifo_lock);
                    atomic_set(&(kp_info->kp_state), KP_STATE_WAITING);
                }
            }
            else
            {
                refcount_dec(&(task->usage));
                atomic_set(&(kp_info->kp_state), 0);
            }
        }
    }
    return 0;
}

/* irqsave相关的kprobe组织信息 */
// static char symbol_lock_irq[MAX_SYMBOL_LEN] = "_raw_spin_lock_irq";
// static char symbol_unlock_irq[MAX_SYMBOL_LEN] = "_raw_spin_unlock_irq";

/* irqsave相关的kprobe组织信息 */
static char symbol_lock_irqsave[MAX_SYMBOL_LEN] = "_raw_spin_lock_irqsave";
static char symbol_unlock_irqrestore[MAX_SYMBOL_LEN] = "_raw_spin_unlock_irqrestore";

// static struct kprobe kp_lock_irq = {
//     .symbol_name = symbol_lock_irq,
//     .pre_handler = handler_lock,
// };

// static struct kprobe kp_unlock_irq = {
//     .symbol_name = symbol_unlock_irq,
//     .pre_handler = handler_unlock,
// };

static struct kprobe kp_lock_irqsave = {
    .symbol_name = symbol_lock_irqsave,
    .pre_handler = handler_lock,
};

static struct kprobe kp_unlock_irqrestore = {
    .symbol_name = symbol_unlock_irqrestore,
    .pre_handler = handler_unlock,
};

extern int spin_lock_irqsave_init(void)
{
    int ret;

    ret = register_kprobe(&kp_lock_irqsave);
    if (ret < 0)
    {
        printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    if (DEBUG)
        printk(KERN_INFO "Planted kprobe at %p\n", kp_lock_irqsave.addr);

    ret = register_kprobe(&kp_unlock_irqrestore);
    if (ret < 0)
    {
        printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    if (DEBUG)
        printk(KERN_INFO "Planted kprobe at %p\n", kp_unlock_irqrestore.addr);
    return 0;
}

extern void spin_lock_irqsave_exit(void)
{
    unregister_kprobe(&kp_lock_irqsave);

    if (DEBUG)
        printk(KERN_INFO "kprobe at %p unregistered\n", kp_lock_irqsave.addr);

    unregister_kprobe(&kp_unlock_irqrestore);
    if (DEBUG)
        printk(KERN_INFO "kprobe at %p unregistered\n", kp_unlock_irqrestore.addr);
}

MODULE_LICENSE("GPL");
