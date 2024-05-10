#ifndef KTHREAD_H
#define KTHREAD_H

#include "lib.h"

extern struct task_struct  *datasave_task;

extern void datasave_task_init(void);
extern void datasave_task_exit(void);

#endif
