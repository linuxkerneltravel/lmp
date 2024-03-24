#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mq_delay.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

BPF_PERCPU_HASH(Time,mqd_t,struct events,1024);//记录事件

BPF_PERCPU_HASH(key,int,mqd_t,1024);//通过pid帮助exit_receive找到mqdes；

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");



SEC("kprobe/do_mq_timedsend")
int BPF_KPROBE(mq_timedsend,mqd_t mqdes, const char __user *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio,
		struct timespec64 *ts)
{
	u64 send_enter_time = bpf_ktime_get_ns();//开始发送信息时间；
	int pid = bpf_get_current_pid_tgid();//发送端pid
	//bpf_map_update_elem(&key, &pid, &mqdes, BPF_ANY);//记录发送端pid与mqdes键值
	//bpf_printk("send_pid: %-8llu ,mqdes: %-8llu, msg_len: %-8d,  msg_prio: %-8lu\n",pid,mqdes,msg_len,msg_prio);

	/*记录数值*/
	struct events val={};
	val.send_pid =  pid;
	val.mqdes = mqdes;
	val.send_enter_time = send_enter_time;
	bpf_map_update_elem(&Time, &mqdes, &val, BPF_ANY);	


	return 0;	
} 	

SEC("kprobe/do_mq_timedreceive")
int BPF_KPROBE(mq_timedreceive_entry,mqd_t mqdes, const char __user *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio,
		struct timespec64 *ts)
{
	u64 rcv_enter_time = bpf_ktime_get_ns();
	int pid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&key, &pid, &mqdes, BPF_ANY);//记录接收端pid与mqdes键值


	return 0;
}

SEC("kretprobe/do_mq_timedreceive")
int BPF_KRETPROBE(mq_timedreceive_exit)
{
	u64 rcv_finish_time = bpf_ktime_get_ns();
	int pid = bpf_get_current_pid_tgid();
	u64 delay;
	/*通过接收进程的pid，获取消息队列的消息号mqdes*/
	mqd_t *mqdes = bpf_map_lookup_elem(&key, &pid);
	if(!mqdes) return 0;

	/*通过mqdes，获取发送消息时记录的信息*/
	struct events *val = bpf_map_lookup_elem(&Time, mqdes);
	if(!val){
		return 0;
	}else delay = (rcv_finish_time - val->send_enter_time)/1000000000;

	struct events *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;

	e->send_pid = val->send_pid;
	e->rcv_pid = pid;//获取到当前进程的pid
	e->mqdes = val->mqdes;
		e->send_enter_time = val->send_enter_time;
		e->rcv_enter_time = val->rcv_enter_time;
		e->rcv_exit_time = rcv_finish_time;
		e->delay = delay;

	bpf_map_delete_elem(&Time, &mqdes);//暂时性删除
	bpf_ringbuf_submit(e, 0);


	return 0;
}
