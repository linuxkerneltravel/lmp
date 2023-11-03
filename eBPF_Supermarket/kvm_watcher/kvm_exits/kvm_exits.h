#ifndef __KVM_EXITS_H
#define __KVM_EXITS_H

#define TASK_COMM_LEN	 16

struct ExitReason {
    int number;
    const char* name;
};

struct event {
	unsigned reason_number;
	char comm[TASK_COMM_LEN];
	unsigned pid;
	unsigned long long duration_ns;
	unsigned tid;
	int count;
	int total;
};

struct reason_info {
    unsigned long long time;
    unsigned long  reason;
	int count;
};


#endif /* __KVM_EXITS_H */
