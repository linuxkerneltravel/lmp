#ifndef WORKQUEUE_H
#define WORKQUEUE_H

#include "lib.h"

extern struct workqueue_struct  *wq;
extern struct work_struct       work;

extern int wq_init(void);
extern void wq_exit(void);

#endif