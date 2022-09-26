#include "../include/lib.h"
#include "../include/xarray.h"
#include "../include/data.h"

struct xarray  *xa;


extern int alloc_xarray(void)
{
    xa = kmalloc(sizeof(*xa), GFP_KERNEL);
    xa_init_flags(xa, XA_FLAGS_ALLOC);
    if(DEBUG) printk("alloc_xa!\n");
    return 0;
}

extern void destroy_xarray()
{
    unsigned long index;
    struct task_info *task_info;
    xa_lock(xa);
    xa_for_each(xa, index, task_info) 
    {
	    free_task_info(task_info);
    }
    xa_unlock(xa);
    xa_destroy(xa);
}

MODULE_LICENSE("GPL");
