#ifndef PROC_H
#define PROC_H

#include "lib.h"

#define OFF     0
#define ON      1

#define  enable         0
#define  threshold      1
#define  savetime       2

// node default val
extern int enable_parm;
extern int threshold_ns;
extern int savetime_s;

extern int node_init(void);
extern void node_exit(void);

extern void root_init(void);
extern void root_exit(void);

extern int checkParm(int oldParm, int newParm, int mode);
extern void changeEnableStatus(int status);

extern int getNodeParm(int mode);

#endif
