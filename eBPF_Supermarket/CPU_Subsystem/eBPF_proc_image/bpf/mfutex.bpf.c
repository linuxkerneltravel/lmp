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
// author: zhangziheng0525@163.com
//
// eBPF kernel-mode code that collects holding lock information of processes

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t ignore_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct mfutex_ctrl);
} mfutex_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_flag);
	__type(value, u64);
} proc_lock SEC(".maps");//记录哪些进程上锁了,便于在lock_exit时找到锁地址

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct proc_flag);
	__type(value, u64);
} proc_unlock SEC(".maps");//记录哪些进程解锁了,便于在unlock_exit时找到锁地址

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct record_lock_key);
	__type(value, int);
} record_lock SEC(".maps");//记录争用锁的全部进程

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct lock_record_key);
	__type(value, int);
} lock_record SEC(".maps");//为了在线程被唤醒时,通过lock_addr, pid 找到cnt ,再通过cnt对record_lock中对应的pid进行操作;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct per_lock_event);
} per_lock_info SEC(".maps");//每个锁的信息事件

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} mfutex_rb SEC(".maps");

#define MUTEX_FLAG  1
#define RWLOCK_FLAG  2
#define SPIN_FLAG  3
#define RCU_FLAG  4
#define FUTEX_FLAG  5
const int ctrl_key = 0;
static inline struct mfutex_ctrl *get_mfutex_ctrl(void) {
    struct mfutex_ctrl *mfutex_ctrl;
    mfutex_ctrl = bpf_map_lookup_elem(&mfutex_ctrl_map, &ctrl_key);
    if (!mfutex_ctrl || !mfutex_ctrl->lock_func) {
        return NULL;
    }
    return mfutex_ctrl;
}
bool push_to_rb(struct per_lock_event *per_lock) {
    struct per_lock_event *e;
    e = bpf_ringbuf_reserve(&mfutex_rb, sizeof(*e), 0);
    if(!e)
        return 0;
    e->lock_ptr = per_lock->lock_ptr;
    e->owner = per_lock->owner;
    e->time = per_lock->time;
    e->type = per_lock->type;
    e->cnt = per_lock->cnt;
    bpf_ringbuf_submit(e, 0);
}
// 用户态互斥锁
/*
 *1:通过__mutex->_lock查看是否已经上锁，如果是，则将该线程记录进record_lock数组中；
 *2:通过__mutex->_owner_id 更新锁的持有者；
 *3:通过__mutex->_type 标识锁的类型；
*/
SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock_enter, struct __pthread_mutex *__mutex)//存申请锁的地址
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) 
        return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    // if(mfutex_ctrl->target_pid == 0 && mfutex_ctrl->target_tgid == 0)//未指定目标进程或线程
    //     return 0;
    // if((mfutex_ctrl->target_pid != 0 && pid!=mfutex_ctrl->target_pid)||
    //     (mfutex_ctrl->target_tgid != 0 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
    //     return 0;
    u64 lock_ptr = (u64)__mutex;

    struct proc_flag proc_flag = {};
    //proc_flag 标注锁的类型
    proc_flag.pid = pid;
    proc_flag.flag = MUTEX_FLAG;
    bpf_map_update_elem(&proc_lock, &proc_flag, &lock_ptr, BPF_ANY);
    bpf_printk("A:lock_addr:0x%x\tpid:%d\n",lock_ptr,pid);  
    return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int BPF_KRETPROBE(pthread_mutex_lock_exit,int ret)
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    // if(mfutex_ctrl->target_pid == 0 && mfutex_ctrl->target_tgid == 0)//未指定目标进程或线程
    //     return 0;
    // if((mfutex_ctrl->target_pid != 0 && pid!=mfutex_ctrl->target_pid)||
    //     (mfutex_ctrl->target_tgid != 0 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
    //     return 0;

    u64 *lock_ptr;
    u64 temp_lock_ptr;
    //找锁
    struct proc_flag proc_flag = {};
    proc_flag.pid = pid;
    proc_flag.flag = MUTEX_FLAG;
    lock_ptr = bpf_map_lookup_elem(&proc_lock, &proc_flag);
    if(!lock_ptr)
        return 0;
    temp_lock_ptr = *lock_ptr;
    // bpf_map_delete_elem(&proc_lock, &proc_flag);
    //对锁进行统计，申请成功，则记录，申请失败，则加入等待队列/阻塞队列；
    if(ret==0){//无人占用锁,
        struct per_lock_event *per_lock = bpf_map_lookup_elem(&per_lock_info, &temp_lock_ptr);
        if(per_lock){//在map中找到
            per_lock->owner = pid;
            per_lock->time = bpf_ktime_get_ns();
            per_lock->cnt = 1;
            push_to_rb(per_lock);
        }else{
            struct per_lock_event per_lock = {};  // 声明结构体变量
            per_lock.lock_ptr = temp_lock_ptr;
            per_lock.type = MUTEX_FLAG;
            per_lock.owner = pid;
            per_lock.time = bpf_ktime_get_ns();
            per_lock.cnt = 1;
            bpf_map_update_elem(&per_lock_info, &temp_lock_ptr, &per_lock, BPF_ANY);   
            push_to_rb(&per_lock);
        }
        bpf_printk("B:lock_addr:0x%x\tpid:%d\t%s\n",temp_lock_ptr,pid,ret==0?"SUCC":"FALSE"); 
        //记录等待该锁的全部进程;
        struct record_lock_key key = {};
        key.lock_ptr = temp_lock_ptr;
        key.cnt = 1;
        bpf_map_update_elem(&record_lock, &key, &pid, BPF_ANY);
    }else{//锁被持有,陷入阻塞或忙等待;
        struct per_lock_event *per_lock = bpf_map_lookup_elem(&per_lock_info, &temp_lock_ptr);
        if(!per_lock){
            return 0;
        }
        per_lock->cnt++;
        //记录等待该锁的全部进程;
        struct record_lock_key key= {};
        key.lock_ptr = temp_lock_ptr;
        key.cnt = per_lock->cnt;
        bpf_map_update_elem(&record_lock, &key, &pid, BPF_ANY);
        struct lock_record_key key2 ={};
        key2.lock_ptr = temp_lock_ptr;
        key2.pid = pid;
        bpf_map_update_elem(&lock_record, &key2, &per_lock->cnt, BPF_ANY); 
        bpf_printk("B:lock_addr:0x%x\tpid:%d\t%s\n",temp_lock_ptr,pid,ret==0?"SUCC":"FALSE"); 
        bpf_printk("lock_addr:0x%x\towner:%d\towner_time:%llu\tcur_pid:%d\n",
                    temp_lock_ptr,per_lock->owner,per_lock->time,pid);  
        //数据存储
        push_to_rb(per_lock);
    }
    return 0;
}

// SEC("uprobe/__pthread_mutex_trylock")
// int BPF_KPROBE(__pthread_mutex_trylock_enter, void *__mutex)
// {
//     record_lock_enter(ignore_tgid,1,1,__mutex,&mfutex_rb,&proc_lock,&lock_ctrl_map);

//     return 0;
// }

// SEC("uretprobe/__pthread_mutex_trylock")
// int BPF_KRETPROBE(__pthread_mutex_trylock_exit,int ret)
// {
//     record_lock_exit(ignore_tgid,2,1,ret,&mfutex_rb,&proc_lock,&locktype,&lock_ctrl_map);
    
//     return 0;
// }

SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock_enter, void *__mutex)
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    // if(mfutex_ctrl->target_pid == 0 && mfutex_ctrl->target_tgid == 0)//未指定目标进程或线程
    //     return 0;
    // if((mfutex_ctrl->target_pid != 0 && pid!=mfutex_ctrl->target_pid)||
    //     (mfutex_ctrl->target_tgid != 0 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
    //     return 0;

    u64 lock_ptr = (u64)__mutex;
    struct proc_flag proc_flag = {};
    //proc_flag 标注锁的类型
    proc_flag.pid = pid;
    proc_flag.flag = MUTEX_FLAG;
    bpf_map_update_elem(&proc_unlock, &proc_flag, &lock_ptr, BPF_ANY);
    bpf_printk("C:lock_addr:0x%x\tpid:%d\n",lock_ptr,pid);  
    return 0;
}

SEC("uretprobe/pthread_mutex_unlock")
int BPF_KRETPROBE(pthread_mutex_unlock_exit,int ret)
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    // if(mfutex_ctrl->target_pid == 0 && mfutex_ctrl->target_tgid == 0)//未指定目标进程或线程
    //     return 0;
    // if((mfutex_ctrl->target_pid != 0 && pid!=mfutex_ctrl->target_pid)||
    //     (mfutex_ctrl->target_tgid != 0 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
    //     return 0;

    u64 *lock_ptr;
    u64 temp_lock_ptr;    
    //找锁
    struct proc_flag proc_flag = {};
    proc_flag.pid = pid;
    proc_flag.flag = MUTEX_FLAG;
    lock_ptr = bpf_map_lookup_elem(&proc_unlock, &proc_flag);
    if(!lock_ptr)
        return 0;
    temp_lock_ptr = *lock_ptr;
    bpf_map_delete_elem(&proc_unlock, &proc_flag); 
    /*返回值为0,表示解锁成功;
     *执行以下操作: 
     *1:将释放锁的进程从record_lock map中删除;
     *2:找到下一个要上锁的线程: 通过遍历被唤醒线程队列和等待锁的队列(record_lock),找到最先被唤醒的线程,就是下一个持有锁的线程;
     *3:更新event,将新持有锁的线程信息同步到event数组;
     */
    if(ret == 0){
        //1:将释放锁的进程从record_lock map中删除;
        struct record_lock_key key = {};
        key.lock_ptr = temp_lock_ptr;
        key.cnt = 1;
        bpf_map_delete_elem(&record_lock, &key);
        bpf_printk("D:lock_addr:0x%x\tpid:%d\t%s\n",temp_lock_ptr,pid,ret==0?"SUCC":"FALSE");
        /*2,3步骤需要到新线程被唤醒时操作;*/
    }
    return 0;
}

//新线程被唤醒时,如果该线程在等待队列(record_lock)中,则说明该线程持有锁;
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    // if(mfutex_ctrl->target_pid == 0 && mfutex_ctrl->target_tgid == 0)//未指定目标进程或线程
    //     return 0;
    // if((mfutex_ctrl->target_pid != 0 && pid!=mfutex_ctrl->target_pid)||
    //     (mfutex_ctrl->target_tgid != 0 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
    //     return 0;
        
    u64 *lock_ptr;
    u64 temp_lock_ptr;

    /*1.在record_lock map中找到当前进程,并将cnt设为1,即持有锁*/
    //1.1找锁
    struct proc_flag proc_flag;
    proc_flag.pid = pid;
    proc_flag.flag = MUTEX_FLAG;
    lock_ptr = bpf_map_lookup_elem(&proc_lock, &proc_flag);
    if(!lock_ptr)
        return 0;
    temp_lock_ptr = *lock_ptr;
    bpf_map_delete_elem(&proc_lock, &proc_flag);

    //1.2找cnt
    int *cnt;
    struct lock_record_key key1 = {} ;
    key1.lock_ptr = temp_lock_ptr;
    key1.pid = pid;
    cnt = bpf_map_lookup_elem(&lock_record, &key1);//找到cnt
    if(!cnt) return 0;

    //1.3 在record_lock map中找到对应的pid并修改其cnt
    struct record_lock_key key2 = {};
    key2.lock_ptr = temp_lock_ptr;
    key2.cnt = *cnt;
    bpf_map_delete_elem(&record_lock, &key2);
    key2.cnt = 1;//修改cnt,表示为锁持有者;
    bpf_map_update_elem(&record_lock, &key2, &lock_ptr, BPF_ANY);
    
    //1.4 修改per_lock_info map中的数值,然后更新event
    struct per_lock_event *per_lock = bpf_map_lookup_elem(&per_lock_info, &temp_lock_ptr);
    if(!per_lock) return 0;
    per_lock->owner = pid;
    per_lock->time = bpf_ktime_get_ns();
    per_lock->cnt--;

    bpf_printk("lock_addr:0x%x\towner:%d\towner_time:%llu\tcur_pid:%d\n",
                temp_lock_ptr,per_lock->owner,per_lock->time,pid);  
    //1.5 数据上传至ringbuffer
    push_to_rb(per_lock);

    return 0;
}