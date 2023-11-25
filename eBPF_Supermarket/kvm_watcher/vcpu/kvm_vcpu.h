#ifndef __KVM_VCPU_H
#define __KVM_VCPU_H

#define TASK_COMM_LEN	 16
struct event {
	char comm[TASK_COMM_LEN];
	unsigned long long dur_hlt_ns;
	unsigned pid;
	unsigned tid;
	bool waited;
	unsigned long long hlt_time;
	//unsigned int hlt_poll_ns;
};
#endif /*  __KVM_VCPU_H */
