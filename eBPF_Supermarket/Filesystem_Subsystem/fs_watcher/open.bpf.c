#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include "open.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义哈希映射
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, u64);
} fdtmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(do_sys_openat2)
{	
    	struct fs_t fs; 
    	pid_t pid;

    	//pid
    	pid = bpf_get_current_pid_tgid() >> 32;
    	fs.pid = pid;
    	
    	//uid
    	fs.uid = bpf_get_current_uid_gid();

	//fd,file descriptor
    	int fd = PT_REGS_RC(ctx);
    	if (fd >= 0)
        	fs.fd = fd;
    	else
        	fs.fd= -1;
        	
        //time
        unsigned long long ts = bpf_ktime_get_ns();
	fs.ts = ts;
        
        //commmand
        //bpf_get_current_comm(&fs.comm, sizeof(fs.comm));
    	
    	//update map
    	//fdtmp.update(&id, &fs);	//bcc语句 
    	bpf_map_update_elem(&fdtmp, &pid, &ts, BPF_ANY);
	
	//从环形缓冲区（ring buffer）中分配一块内存来存储一个名为 struct fs_t 类型的数据，并将该内存块的指针赋值给指针变量 e
	struct fs_t *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;	
	
	//给变量e赋值
	e->pid = fs.pid;
	e->uid = fs.uid;
	e->fd = fs.fd;
	e->ts = fs.ts;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	
	// 成功地将其提交到用户空间进行后期处理
	bpf_ringbuf_submit(e, 0);

    	return 0;
}

