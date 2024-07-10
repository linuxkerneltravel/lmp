// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: albert_xuu@163.com zhangxy1016304@163.com zhangziheng0525@163.com

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cpu_watcher.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;
BPF_HASH(send_msg1,pid_t,struct send_events,1024);//记录pid->u_msg_ptr的关系；do_mq_timedsend入参
BPF_HASH(send_msg2,u64,struct send_events,1024);//记录msg->time的关系；
BPF_HASH(rcv_msg1,pid_t,struct rcv_events,1024);//记录pid->u_msg_ptr的关系；do_mq_timedsend入参
BPF_ARRAY(mq_ctrl_map,int,struct mq_ctrl,1);
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct mq_ctrl *get_mq_ctrl(void) {
    struct mq_ctrl *mq_ctrl;
    mq_ctrl = bpf_map_lookup_elem(&mq_ctrl_map, &ctrl_key);
    if (!mq_ctrl || !mq_ctrl->mq_func) {
        return NULL;
    }
    return mq_ctrl;
}


// int print_send_info(struct send_events * mq_send_info,int flag){
// 	bpf_printk("---------------------test----------------------------test--------------------------test--------------------------------------------test---------------------test---------------------test\n");
// 	bpf_printk("send_msg_prio: %-8lu\n",mq_send_info->msg_prio);
// 	bpf_printk("mqdes: %-08lu  send_pid: %-08lu  send_enter_time: %-16lu\n",mq_send_info->mqdes,mq_send_info->send_pid,mq_send_info->send_enter_time);
// 	if(flag > 0){
// 		bpf_printk("u_msg_ptr: 0x%08lx  src: 0x%08lx\n",mq_send_info->u_msg_ptr,mq_send_info->src);
// 		if(flag==2)	bpf_printk("Key_msg_ptr: 0x%08lx  \n",mq_send_info->Key_msg_ptr);
// 	}
// 	bpf_printk("---------------------test----------------------------test--------------------------test--------------------------------------------test---------------------test---------------------test\n");
// 	return 0;
// }

// int print_rcv_info(struct rcv_events * mq_rcv_info,int flag){
// 	bpf_printk("---------------------test----------------------------test--------------------------test--------------------------------------------test---------------------test---------------------test\n");
// 	bpf_printk("rcv_msg_prio: %-8lu\n",mq_rcv_info->msg_prio);	
// 	bpf_printk("mqdes: %-08lu  rcv_pid: %-08lu  rcv_enter_time: %-16lu\n",mq_rcv_info->mqdes,mq_rcv_info->rcv_pid,mq_rcv_info->rcv_enter_time);
// 	if(flag > 0){
// 		bpf_printk("u_msg_ptr: 0x%08lx  dest: 0x%08lx\n",mq_rcv_info->u_msg_ptr,mq_rcv_info->dest);
// 		if(flag==2)	bpf_printk("Key_msg_ptr: 0x%08lx  \n",mq_rcv_info->Key_msg_ptr);
// 	}
// 	bpf_printk("---------------------test----------------------------test--------------------------test--------------------------------------------test---------------------test---------------------test\n");
// 	return 0;
// }
	

/*获取 mq_send_info -> send_time send_pid mdqes u_msg_ptr msg_len msg_prio*/
SEC("kprobe/do_mq_timedsend")
int BPF_KPROBE(mq_timedsend,mqd_t mqdes, const char *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio,
		struct timespec64 *ts)
{
	struct mq_ctrl *mq_ctrl = get_mq_ctrl();
	u64 send_enter_time = bpf_ktime_get_ns();//开始发送信息时间；
	int pid = bpf_get_current_pid_tgid();//发送端pid

	/*将消息暂存至send_events结构体中*/
	struct send_events mq_send_info ={};
	mq_send_info.send_pid= pid;
	mq_send_info.send_enter_time = send_enter_time;
		mq_send_info.mqdes= mqdes;
		mq_send_info.msg_len = msg_len;
		mq_send_info.msg_prio = msg_prio;
		mq_send_info.u_msg_ptr = u_msg_ptr;

	bpf_map_update_elem(&send_msg1, &pid, &mq_send_info, BPF_ANY);//pid->u_msg_ptr
	return 0;	
} 	

/*仅获取mq_send_info -> src*/
SEC("kprobe/load_msg")
int BPF_KPROBE(load_msg_enter,const void *src, size_t len){
	struct mq_ctrl *mq_ctrl = get_mq_ctrl();
	int pid = bpf_get_current_pid_tgid();//发送端pid
	/*记录load入参src*/
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg1, &pid);
	if(!mq_send_info){
		return 0;
	}else{
		mq_send_info->src = src;
	} 	
	return 0;		
}

/*获取消息块作为key，并建立 message -> mq_send_info 的哈希表*/
SEC("kretprobe/load_msg")
int BPF_KRETPROBE(load_msg_exit,void *ret){
	struct mq_ctrl *mq_ctrl = get_mq_ctrl();
	int pid = bpf_get_current_pid_tgid();//发送端pid
	/*构建消息块结构体，作为key*/
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg1, &pid);
	if(!mq_send_info){
		return 0;
	}

	/*make key*/
	u64 Key_msg_ptr;
	if(mq_send_info->u_msg_ptr == mq_send_info->src && pid == mq_send_info->send_pid){
		/*该load_msg为do_mq_timedsend调用*/
		Key_msg_ptr =(u64)ret;
		mq_send_info->Key_msg_ptr = Key_msg_ptr;
	}
	else {
		return 0;
	}
	/*已经获得key*/
	bpf_map_update_elem(&send_msg2, &Key_msg_ptr, mq_send_info, BPF_ANY);//key_messege->mq_send_info;
	return 0;		
}

SEC("kretprobe/do_mq_timedsend")
int BPF_KRETPROBE(do_mq_timedsend_exit,void *ret)
{
	struct mq_ctrl *mq_ctrl = get_mq_ctrl();
	bpf_printk("do_mq_timedsend_exit----------------------------------------------------------------\n");
	u64 send_exit_time = bpf_ktime_get_ns();//开始发送信息时间；
	int pid = bpf_get_current_pid_tgid();//发送端pid
	u64 Key; 

	struct send_events *mq_send_info1 = bpf_map_lookup_elem(&send_msg1, &pid);
	if(!mq_send_info1){
		return 0;
	}
	Key = mq_send_info1->Key_msg_ptr;
	struct send_events *mq_send_info2 = bpf_map_lookup_elem(&send_msg2, &Key);
	if(!mq_send_info2){
		return 0;
	}
	mq_send_info2->send_exit_time = send_exit_time;
	bpf_map_delete_elem(&send_msg1,&pid);
	return 0;	
} 
/*-----------------------------------------------------------------------------发送端--------------------------------------------------------------------------------------------------------*/
/*																				分界   																										*/
/*-----------------------------------------------------------------------------接收端--------------------------------------------------------------------------------------------------------*/                                                                                                                                                                                     
/*接收端*/
SEC("kprobe/do_mq_timedreceive")
int BPF_KPROBE(mq_timedreceive_entry,mqd_t mqdes, const char __user *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio,
		struct timespec64 *ts)
{
	struct mq_ctrl *mq_ctrl = get_mq_ctrl();
	u64 rcv_enter_time = bpf_ktime_get_ns();
	int pid = bpf_get_current_pid_tgid();

	/*赋值*/
	struct rcv_events mq_rcv_info ={};
	mq_rcv_info.rcv_pid= pid;
	mq_rcv_info.rcv_enter_time = rcv_enter_time;
		mq_rcv_info.mqdes= mqdes;
		mq_rcv_info.u_msg_ptr = u_msg_ptr;
	bpf_map_update_elem(&rcv_msg1, &pid, &mq_rcv_info, BPF_ANY);//pid->u_msg_ptr	

	return 0;
}

SEC("kprobe/store_msg")
int BPF_KPROBE(store_msg,void __user *dest, struct msg_msg *msg, size_t len)
{
	struct mq_ctrl *mq_ctrl = get_mq_ctrl();
	int pid = bpf_get_current_pid_tgid();
	
	/*make key*/
	u64 Key_msg_ptr = (u64)msg;
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg2, &Key_msg_ptr);
	if(!mq_send_info){
		return 0;
	}
	
	struct rcv_events *mq_rcv_info = bpf_map_lookup_elem(&rcv_msg1, &pid);
	if(!mq_rcv_info){
		return 0;
	}
	/*拿到mq_rcv_info*/
	if(dest == mq_rcv_info->u_msg_ptr && pid == mq_rcv_info->rcv_pid){
		mq_rcv_info->Key_msg_ptr = Key_msg_ptr;
		mq_rcv_info->dest = dest;
		mq_rcv_info->msg_prio = BPF_CORE_READ(msg,m_type);
		mq_rcv_info->msg_len = BPF_CORE_READ(msg,m_ts);
	}else{
		return 0;
	}
	return 0;
}

SEC("kretprobe/do_mq_timedreceive")
int BPF_KRETPROBE(do_mq_timedreceive_exit,void *ret){
	struct mq_ctrl *mq_ctrl = get_mq_ctrl();
	u64 rcv_exit_time = bpf_ktime_get_ns();
	int pid = bpf_get_current_pid_tgid();
	u64 send_enter_time,delay;
	u64 Key;
	
	/*获取发送端、接收端信息*/
	struct rcv_events *mq_rcv_info = bpf_map_lookup_elem(&rcv_msg1, &pid);
	if(!mq_rcv_info){
		return 0;
	}	
	Key = mq_rcv_info->Key_msg_ptr;
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg2,&Key);
	if(!mq_send_info){
		return 0;
	}

	/*ringbuffer传值*/
	struct mq_events *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;
	e->send_pid = mq_send_info->send_pid;
	e->rcv_pid = pid;
	e->mqdes = mq_send_info->mqdes;
		e->msg_len = mq_send_info->msg_len;
		e->msg_prio = mq_send_info->msg_prio;

		e->send_enter_time = mq_send_info->send_enter_time;
		e->send_exit_time = mq_send_info->send_exit_time;
		e->rcv_enter_time = mq_rcv_info->rcv_enter_time;
		e->rcv_exit_time = rcv_exit_time;
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&send_msg2, &Key);//暂时性删除
	bpf_map_delete_elem(&rcv_msg1,&pid);//删除rcv_msg1  map;
	return 0;

}
