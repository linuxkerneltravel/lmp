#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mq_delay.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

BPF_PERCPU_HASH(Time,mqd_t,struct events,1024);//记录事件

BPF_PERCPU_HASH(key,int,mqd_t,1024);//通过pid帮助exit_receive找到mqdes；

BPF_PERCPU_HASH(get_msg1,pid_t,struct events,1024);//记录pid->u_msg_ptr的关系；do_mq_timedsend入参
BPF_PERCPU_HASH(get_msg,struct msg_msg,u64,1024);//记录msg->time的关系；
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("kprobe/do_mq_timedsend")
int BPF_KPROBE(mq_timedsend,mqd_t mqdes, const char *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio,
		struct timespec64 *ts)
{
	u64 send_enter_time = bpf_ktime_get_ns();//开始发送信息时间；
	int pid = bpf_get_current_pid_tgid();//发送端pid

	/*赋值*/
	struct events mq_info ={};
	mq_info.send_pid= pid;
	mq_info.send_enter_time = send_enter_time;
		mq_info.mqdes= mqdes;
		mq_info.msg_len = msg_len;
		mq_info.msg_prio = msg_prio;
		mq_info.u_msg_ptr = u_msg_ptr;

	bpf_map_update_elem(&get_msg1, &pid, &mq_info, BPF_ANY);//pid->u_msg_ptr
	// bpf_map_update_elem(&get_msg2, &pid, &send_enter_time, BPF_ANY);//pid->time	
	return 0;	
} 	
SEC("kprobe/load_msg")
int BPF_KPROBE(load_msg_enter,const void *src, size_t len){
	int pid = bpf_get_current_pid_tgid();//发送端pid
	/*记录load入参src*/
	struct events *mq_info = bpf_map_lookup_elem(&get_msg1, &pid);
	if(!mq_info){
		return 0;
	}else{
		mq_info->src = src;
	} 	
	bpf_map_update_elem(&get_msg1, &pid, mq_info, BPF_ANY);//pid->src

	return 0;		
}
SEC("kretprobe/load_msg")
int BPF_KRETPROBE(load_msg_exit,void *ret){
	int pid = bpf_get_current_pid_tgid();//发送端pid
	/*构建消息块结构体，作为key*/
	struct msg_msg *tmp =(struct msg_msg *)ret;
	struct events *mq_info = bpf_map_lookup_elem(&get_msg1, &pid);
	if(!mq_info){
		bpf_printk("erro2");
		return 0;
	}
	/*make key*/
	mq_info->Key_msg_ptr = (struct msg_msg){0};
	mq_info->Key_msg_ptr.m_list =  BPF_CORE_READ(tmp,m_list);
	mq_info->Key_msg_ptr.m_type =  BPF_CORE_READ(tmp,m_type);
	mq_info->Key_msg_ptr.m_ts =  BPF_CORE_READ(tmp,m_ts);
	mq_info->Key_msg_ptr.next =  BPF_CORE_READ(tmp,next);
	mq_info->Key_msg_ptr.security =  BPF_CORE_READ(tmp,security);
	mq_info->Key_msg_ptr.m_type = mq_info->msg_prio;
	mq_info->Key_msg_ptr.m_ts = mq_info->msg_len;

	struct events *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;

	e->send_pid = mq_info->send_pid;
	e->send_enter_time = mq_info->send_enter_time;
	e->mqdes = mq_info->mqdes;
	e->msg_len = mq_info->msg_len;
	e->msg_prio = mq_info->msg_prio;
	e->u_msg_ptr = mq_info->u_msg_ptr;
	e->src = mq_info->src;

	e->m_type = BPF_CORE_READ(tmp,m_type);
	e->m_ts = BPF_CORE_READ(tmp,m_ts);
	e->Key_msg_ptr = mq_info->Key_msg_ptr;
	bpf_map_delete_elem(&get_msg1, &pid);//暂时性删除

	bpf_ringbuf_submit(e, 0);

	return 0;		
}