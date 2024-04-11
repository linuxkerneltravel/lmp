#include "../include/lib.h"
#include "../include/objpool.h"

struct obj_pool *kp_pool;

/* obj_pool对象池的初始化 */
static struct obj_pool *init_obj_pool(unsigned int obj_size, unsigned int pg_order)
{
    struct obj_pool *obj_pool;

    obj_pool = kmalloc(sizeof(*obj_pool), GFP_KERNEL);

    obj_pool->pg_addr = __get_free_pages(GFP_KERNEL | __GFP_ZERO, pg_order);
    if (!obj_pool->pg_addr)
    {
        kfree(obj_pool);
        printk(KERN_ERR "obj_pool allocate error!\n");
        return NULL;
    }

    obj_pool->pg_order = pg_order;
    obj_pool->obj_size = obj_size;
    obj_pool->max_idx = (PAGE_SIZE << pg_order) / obj_size;

    atomic_set(&(obj_pool->next_idx), 0);

    return obj_pool;
}

/* 用于在对象池obj_pool中获得一个对象,返回地址 */
static unsigned long new_obj(struct obj_pool *obj_pool)
{
    unsigned int now_idx = atomic_fetch_inc(&(obj_pool->next_idx));

    now_idx = now_idx % obj_pool->max_idx;

    return (now_idx * obj_pool->obj_size + obj_pool->pg_addr);
}

/* 用于获取对象池中指定index位置的对象 */
static unsigned long get_index_obj(struct obj_pool *obj_pool, unsigned int index)
{
    if (index >= obj_pool->max_idx)
        return 0;
    return (index * obj_pool->obj_size + obj_pool->pg_addr);
}

/* 销毁对象池obj_pool,在这之前应该对对象池中所有的对象进行处理 */
static void free_obj_pool(struct obj_pool *obj_pool)
{
    if (obj_pool)
    {
        free_pages(obj_pool->pg_addr, obj_pool->pg_order);
        kfree(obj_pool);
        obj_pool = NULL;
    }
}

extern void alloc_kp_pool(void)
{
    kp_pool = init_obj_pool(sizeof(struct kp_info), 1);
    if (!kp_pool)
    {
        printk(KERN_ERR "init_kp_pool failed!\n");
    }
}

/* 从kp_pool对象池中获得一个新的kp_info对象 */
extern struct kp_info *new_kp_info(struct obj_pool *kp_pool)
{
    return (struct kp_info *)(new_obj(kp_pool));
}

/* 从kp_pool对象池中获得指定位置的kp_info对象 */
extern struct kp_info *get_index_kp_info(struct obj_pool *kp_pool, unsigned int index)
{
    return (struct kp_info *)(get_index_obj(kp_pool, index));
}

/* 销毁kp_pool对象池,需要先消去所有未被处理的对象的引用计数 */
/* 此时应该让work完全退出之后再去执行 */
extern void destroy_kp_pool(void)
{
    unsigned int index, max_idx;
    struct kp_info *kp_info;

    max_idx = kp_pool->max_idx;
    for (index = 0; index < max_idx; index++)
    {
        kp_info = get_index_kp_info(kp_pool, index);

        if (atomic_cmpxchg(&(kp_info->kp_state), KP_STATE_WAITING, KP_STATE_WRITING) == KP_STATE_WAITING)
        {
            refcount_dec(&(kp_info->task->usage));

            atomic_set(&(kp_info->kp_state), 0); // tt
        }
    }

    free_obj_pool(kp_pool);
}

MODULE_LICENSE("GPL");
