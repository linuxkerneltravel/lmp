#include "vmlinux.h"
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "process_limit.h"
//#include "pfilter.h"


#define FILTER_SIZE 4096


struct filter_common{
	__u32 pid;
	__u32 pidset;
	__u32 eventtype;

};

struct msg_common {
        __u8 op;
        __u8 flags; // internal flags not exported
        __u8 pad[2];
        __u32 size;
        __u64 ktime;
};

struct msg_execve_key {   
        __u32 pid;
        __u8 pad[4];
        __u64 ktime;
} __attribute__((packed));

struct msg_capabilities {
        union {
                struct {
                        __u64 permitted;
                        __u64 effective;
                        __u64 inheritable;
                };
                __u64 c[3];
        };
};

struct msg_generic_kprobe {
        struct msg_common common;
        struct msg_execve_key current;
        struct msg_capabilities caps;
        __u64 id;
        __u64 thread_id;
        __u64 action;
        char args[24000];
        unsigned long a0, a1, a2, a3, a4;
        __u64 curr;   
        __u64 pass;
        //bool active[MAX_CONFIGURED_SELECTORS];
        __u64 match_cap;
};


struct caps_filter {
        u32 ty; // (i.e. effective, inheritable, or permitted) 
        u32 op; // op (i.e. op_filter_in or op_filter_notin) 
        u32 ns; // If ns == 0 <=> IsNamespaceCapability == false. Otheriwse it contains the value of host user namespace. 
        u64 val; // OR-ed capability values 
} __attribute__((packed));


struct execve_map_value {    //look here
        struct msg_execve_key key;
        struct msg_execve_key pkey;
        __u32 flags;
        __u32 nspid;
        __u32 binary;
        __u32 pad;
        struct msg_capabilities caps;
} __attribute__((packed)) __attribute__((aligned(8)));


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, pid_t);
	__type(value, struct event);
}execs SEC(".maps");


struct {
	__uint(type,BPF_MAP_TYPE_HASH);
	__uint(max_entries,128);
	__type(key,pid_t);
	__type(value,struct execve_map_value);
}execve SEC(".maps");


struct {
        __uint(type,BPF_MAP_TYPE_ARRAY);
        __uint(max_entries,1);
        __type(key,pid_t);
        __type(value,struct filter_common);
}filter SEC(".maps");

struct {
        __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries,1);
        __type(key,pid_t);
        __type(value,struct msg_generic_kprobe);
}process_call SEC(".maps");



SEC("kprobe/__x64_sys_write")
int prog(struct trace_event_raw_sys_enter *ctx)
{
	struct event *event;
	pid_t pid;
	u64 id;
	uid_t uid = (u32) bpf_get_current_uid_gid();

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	
	struct execve_map_value *init;
	struct msg_generic_kprobe *msg;
	int ret, zero = 0;
	bool pass = false;
	struct caps_filter *caps;
	__u64 caps_curr;
	__u64 caps_init;

	msg = bpf_map_lookup_elem(&process_call, &zero);
	if (!msg)
		return 0;

          if (bpf_map_update_elem(&execve, &pid, &((struct execve_map_value){}), 1)) {
                return 0;
        }


	init = bpf_map_lookup_elem(&execve, &pid);
	if(!init)
		return 0;

	__u32 *f = bpf_map_lookup_elem(&filter,&zero);
	__u32 ty;	

	caps = (struct caps_filter *)((u64)f);	
	
	ty = caps->ty;

	caps_curr = msg->caps.c[ty];

	caps_init = init->caps.c[ty];
	




	        if (bpf_map_update_elem(&execs, &pid, &((struct event){}), 1)) {
                return 0;
        }


 event = bpf_map_lookup_elem(&execs, &pid);
	if (!event) {
		return 0;
	}

	event->pid = pid;
	event->uid = uid;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	
	if(caps_curr != caps_init)
       {
                bpf_send_signal(9);
        }




	return 0;
}

char LICENSE[] SEC("license") = "GPL";
