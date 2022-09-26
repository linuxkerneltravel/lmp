#ifndef KPROBE_H
#define KPROBE_H

#include "lib.h"
#include "percpu.h"

#define NUM_STACK_ENTRIES       64
#define MAX_SYMBOL_LEN          64

#define KP_STATE_WAITING        0x1
#define KP_STATE_READING        0x1 << 1
#define KP_STATE_WRITING        0x1 << 2

/* 要保存的结构体kp_info */
struct kp_info {
    atomic_t            kp_state;
    struct task_struct  *task;
    unsigned long       lock_addr;
    unsigned int        cpu;
    unsigned long       time_stamp;
    unsigned long       delta;
    unsigned int        num_entries;
    unsigned long       stack_entries[NUM_STACK_ENTRIES];
};

//irq
extern int spin_lock_irq_init(void);
extern void spin_lock_irq_exit(void);

//irq_save
extern int spin_lock_irqsave_init(void);
extern void spin_lock_irqsave_exit(void);

#endif