#ifndef KFIFO_H
#define KFIFO_H

#include "lib.h"

#define FIFO_SIZE  2048

//kfifo
extern struct kfifo kfifo;
extern spinlock_t kfifo_lock;

extern int kfifoPutData(void *data, unsigned int size);
extern int fifo_init(void);
extern void fifo_exit(void);

#endif
