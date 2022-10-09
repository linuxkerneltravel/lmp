#ifndef OBJPOOL_H
#define OBJPOOL_H

#include "lib.h"
#include "kprobe.h"

/* obj_pool对象池,用于充当buffer */
struct obj_pool {
    unsigned long       pg_addr;
    unsigned int        pg_order;
    unsigned int        obj_size;
    unsigned int        max_idx;
    atomic_t            next_idx;
};

extern struct obj_pool *kp_pool;

extern void alloc_kp_pool(void); 
extern struct kp_info * new_kp_info(struct obj_pool *kp_pool);
extern struct kp_info * get_index_kp_info(struct obj_pool *kp_pool, unsigned int index);
extern void destroy_kp_pool(void);

#endif
