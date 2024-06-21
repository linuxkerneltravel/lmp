#ifndef __OPEN_H
#define __OPEN_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
	int pid_;
	char path_name_[path_size];
	int n_;
	char comm[TASK_COMM_LEN];
};

#endif /* __OPEN_H */