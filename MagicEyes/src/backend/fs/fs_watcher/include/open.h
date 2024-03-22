#ifndef __OPEN_H
#define __OPEN_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct fs_t {
	int pid;
	unsigned long long uid;
    	int fd;
    	unsigned long long ts;
    	char comm[TASK_COMM_LEN];
};

#endif /* __OPEN_H */