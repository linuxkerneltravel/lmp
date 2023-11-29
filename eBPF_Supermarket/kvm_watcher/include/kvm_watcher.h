#ifndef __KVM_WATCHER_H
#define __KVM_WATCHER_H

#define TASK_COMM_LEN	 16

struct process{
	unsigned pid;
	unsigned tid;
	char comm[TASK_COMM_LEN];
};
struct vcpu_wakeup_event {
	struct process process;
	unsigned long long dur_hlt_ns;
	bool waited;
	unsigned long long hlt_time;
};

struct exit_event {
    struct process process;
	unsigned reason_number;
	unsigned long long duration_ns;
	int count;
	int total;
};

struct ExitReason {
    int number;
    const char* name;
};

struct reason_info {
    unsigned long long time;
    unsigned long  reason;
	int count;
};

#endif /* __KVM_WATCHER_H */