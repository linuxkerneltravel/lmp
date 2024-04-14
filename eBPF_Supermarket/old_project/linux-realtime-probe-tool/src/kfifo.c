#include "../include/lib.h"
#include "../include/kfifo.h"
#include "../include/kprobe.h"

struct kfifo kfifo;
spinlock_t kfifo_lock;

extern int fifo_init(void)
{
    int ret;
    ret = kfifo_alloc(&kfifo, sizeof(struct kp_info *) * FIFO_SIZE, GFP_KERNEL);
    if (ret)
    {
        printk(KERN_ERR "Failed kfifo_alloc\n");
        return -1;
    }
    spin_lock_init(&kfifo_lock);
    return 0;
}

extern int kfifoPutData(void *data, unsigned int size)
{
    int ret;
    ret = kfifo_in(&kfifo, &data, size);
    if (ret<=0)
    {
        printk(KERN_ERR "Failed kfifo in, fifo is full\n");
        return -1;
    }
    return 0;
}

extern void fifo_exit(void)
{
    kfifo_free(&kfifo);
}

MODULE_LICENSE("GPL");
