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
	__type(value, struct per_request);
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
	__uint(max_entries,528 * 10240);
} mfutex_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct lock_record_key);
	__type(value, struct per_request);
} futex_wait_queue SEC(".maps");//记录futex陷入内核
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct lock_record_key);
	__type(value, struct per_request);
} futex_wake_queue SEC(".maps");//记录futex陷入内核

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

/*1.尝试申请锁
 *1.1:将申请锁的进程加入等待队列，并标记相关信息；
*/
SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock_enter, void *__mutex)//存申请锁的地址
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) 
        return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if(mfutex_ctrl->target_pid == -1 && mfutex_ctrl->target_tgid == -1)//未指定目标进程或线程
        return 0;
    if((mfutex_ctrl->target_pid != -1 && pid!=mfutex_ctrl->target_pid)||
        (mfutex_ctrl->target_tgid != -1 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
        return 0;

    u64 lock_ptr = (u64)__mutex;
    int cnt;
    /*1.将锁地址信息与进程pid记录在proc_lock map中*/
    struct proc_flag proc_flag = {};
    proc_flag.pid = pid;
    proc_flag.flag = MUTEX_FLAG;
    bpf_map_update_elem(&proc_lock, &proc_flag, &lock_ptr, BPF_ANY);

    /*2.对per_lock_info map中的信息进行读取更新或增加，包括cnt*/
    struct per_lock_event * per_lock_event = bpf_map_lookup_elem(&per_lock_info, &lock_ptr);
    if(per_lock_event){
        per_lock_event->cnt++;
        cnt = per_lock_event->cnt;
    }else{
        struct per_lock_event new_per_lock = {};
        new_per_lock.lock_ptr = lock_ptr;
        new_per_lock.type = MUTEX_FLAG;
        new_per_lock.cnt = 1;
        cnt = 1;
        bpf_map_update_elem(&per_lock_info, &lock_ptr, &new_per_lock, BPF_ANY);
    }
    /*3.将 单个线程请求信息块 放入 请求等待队列record_lock 以及lock_record map */
    struct per_request per_request = {};
    per_request.pid = pid;
    per_request.start_request_time = bpf_ktime_get_ns();
    struct record_lock_key key = {};
    key.lock_ptr = lock_ptr;
    key.cnt = cnt;
    bpf_map_update_elem(&record_lock, &key, &per_request, BPF_ANY);
    bpf_printk("Push_info:pid:%d ,lock_ptr:%lu, cnt:%d\n",per_request.pid,key.lock_ptr,key.cnt);
    //用于通过lock_ptr 和pid 找到cnt
    struct lock_record_key key2 ={};
    key2.lock_ptr = lock_ptr;
    key2.pid = pid;
    bpf_map_update_elem(&lock_record, &key2, &cnt, BPF_ANY);
    return 0;
}

/*2.申请锁成功
 *2.1:更新持有锁信息，将等待对列中对应的进程标记为持有；
*/
SEC("uretprobe/pthread_mutex_lock")
int BPF_KRETPROBE(pthread_mutex_lock_exit,int ret)
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    if(ret) 
        return 0;
    if(mfutex_ctrl->target_pid == -1 && mfutex_ctrl->target_tgid == -1)//未指定目标进程或线程
        return 0;
    if((mfutex_ctrl->target_pid != -1 && pid!=mfutex_ctrl->target_pid)||
        (mfutex_ctrl->target_tgid != -1 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
        return 0;

    u64 *lock_ptr;
    u64 temp_lock_ptr;
    u64 ts = bpf_ktime_get_ns();
    /*1.找到锁的地址*/
    struct proc_flag proc_flag = {};
    proc_flag.pid = pid;
    proc_flag.flag = MUTEX_FLAG;
    lock_ptr = bpf_map_lookup_elem(&proc_lock, &proc_flag);
    if(!lock_ptr) return 0;
    temp_lock_ptr = *lock_ptr;

    /*2.找到当前线程在record_lock map中的位置，即cnt*/
    int *cnt;
    struct lock_record_key key1 = {};
    key1.lock_ptr = temp_lock_ptr;
    key1.pid = pid;
    cnt = bpf_map_lookup_elem(&lock_record, &key1);//找到cnt
    if(!cnt) return 0;

    /*3.通过 cnt和lock_ptr 在record_lock map中找到对应的线程信息块，并更新*/
    struct record_lock_key key2 = {};
    key2.lock_ptr = temp_lock_ptr;
    key2.cnt = *cnt;
    struct per_request *per_request = bpf_map_lookup_elem(&record_lock, &key2);
    if(!per_request) return 0;
    bpf_map_delete_elem(&record_lock, &key2);
    key2.cnt = 1;
    per_request->start_hold_time = ts;//标志着开始占有锁
    per_request->wait_delay = ts - per_request->start_request_time;
    bpf_map_update_elem(&record_lock, &key2, per_request, BPF_ANY);

    /*4.更新per_lock_info map中的信息，并传送到ringbuf中*/
    struct per_lock_event *per_lock_event = bpf_map_lookup_elem(&per_lock_info, &temp_lock_ptr);
    if(!per_lock_event) return 0;
    per_lock_event->owner = pid;
    per_lock_event->start_hold_time = ts;
    bpf_map_update_elem(&per_lock_info, &temp_lock_ptr, per_lock_event, BPF_ANY);

    //数据传送到ringbuf；
    struct per_lock_event *e;
    e = bpf_ringbuf_reserve(&mfutex_rb, sizeof(*e), 0);
    if(!e)
        return 0;
    e->lock_ptr = per_lock_event->lock_ptr;
    e->owner = per_lock_event->owner;
    e->last_owner = per_lock_event->last_owner;
    e->start_hold_time = per_lock_event->start_hold_time;
    e->type = per_lock_event->type;
    e->cnt = per_lock_event->cnt;
    e->last_hold_delay = per_lock_event->last_hold_delay;
    bpf_printk("In Push_to_rb lock_ptr %llu,per_cnt:%d,owner:%d,last_owner:%d,last_hold_time:%lu\n",e->lock_ptr,e->cnt,e->owner,
                e->last_owner,e->last_hold_delay);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*尝试解锁
 *1.将等待对列中对应的解锁进程删除，并更新该进程持有锁的时间；
*/
SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock_enter, void *__mutex)
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) return 0;

    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;

    if(mfutex_ctrl->target_pid == -1 && mfutex_ctrl->target_tgid == -1)//未指定目标进程或线程
        return 0;
    if((mfutex_ctrl->target_pid != -1 && pid!=mfutex_ctrl->target_pid)||
        (mfutex_ctrl->target_tgid != -1 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
        return 0;

    u64 lock_ptr = (u64)__mutex;
    u64 ts = bpf_ktime_get_ns();

    /*1.通过 cnt和lock_ptr 在record_lock map中找到对应的线程信息块，并删除在队列中的记录*/
    struct record_lock_key key2 = {};
    key2.lock_ptr = lock_ptr;
    key2.cnt = 1;
    struct per_request *per_request = bpf_map_lookup_elem(&record_lock, &key2);
    if(!per_request) return 0;
    bpf_map_delete_elem(&record_lock, &key2);

    /*2.将该线程持有锁的信息同步在per_lock map 中*/
    struct per_lock_event *per_lock_event = bpf_map_lookup_elem(&per_lock_info, &lock_ptr);
    if(!per_lock_event) return 0;
    per_lock_event->last_owner = pid;
    // per_lock_event->last_start_hold_time = ts;
    per_lock_event->last_hold_delay = ts - per_request->start_hold_time;//持有锁的时间
    bpf_map_update_elem(&per_lock_info, &lock_ptr, per_lock_event, BPF_ANY);
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

// SEC("tracepoint/syscall/sys_enter_futex")
// int trace_sys_enter_futex(struct sys_futex_args ctx){

// }

/*1.将线程加入等待队列，并记录*/
SEC("kprobe/futex_wait")
int BPF_KPROBE(trace_futex_wait, 
                u32 *uaddr, unsigned int flags, 
                u32 val, ktime_t *abs_time, u32 bitset) 
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) 
        return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    
    if(mfutex_ctrl->target_pid == -1 && mfutex_ctrl->target_tgid == -1)//未指定目标进程或线程
        return 0;
    if((mfutex_ctrl->target_pid != -1 && pid!=mfutex_ctrl->target_pid)||
        (mfutex_ctrl->target_tgid != -1 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
        return 0;

    u64 lock_ptr = (u64)uaddr;
    int cpu = bpf_get_smp_processor_id();//获取当前cpu

    /*1.将 单个线程请求信息块 放入 请求等待队列futex_wait_queue*/
    struct per_request per_request = {};
    per_request.pid = pid;
    per_request.start_request_time = bpf_ktime_get_ns();
    per_request.cpu_id = cpu;
    struct lock_record_key key = {};
    key.lock_ptr = lock_ptr;
    key.pid = pid;
    bpf_map_update_elem(&futex_wait_queue, &key, &per_request, BPF_ANY);
    // bpf_printk("Push_info:pid:%d ,lock_ptr:%lu, cnt:%d\n",per_request.pid,key.lock_ptr,key.cnt);
    return 0;
}

/*2.将线程加入唤醒队列，从等待队列中删除
 *2.1 将执行futex_wake的线程pid与锁地址进行匹配，便于在后面futex_wake_mark找到锁地址
 */
SEC("kprobe/futex_wake")
int BPF_KPROBE(trace_futex_wake_enter, 
                u32 *uaddr, unsigned int flags, 
                int nr_wake, u32 bitset) 
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) 
        return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    
    if(mfutex_ctrl->target_pid == -1 && mfutex_ctrl->target_tgid == -1)//未指定目标进程或线程
        return 0;
    if((mfutex_ctrl->target_pid != -1 && pid!=mfutex_ctrl->target_pid)||
        (mfutex_ctrl->target_tgid != -1 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
        return 0;

    u64 lock_ptr = (u64)uaddr;
    struct proc_flag key={};
    key.pid = pid;
    key.flag = FUTEX_FLAG;
    bpf_map_update_elem(&proc_unlock, &key, &lock_ptr, BPF_ANY);//将锁地址存在proc_unlock map中
    return 0;
}
/*2.将线程加入唤醒队列，从等待队列中删除
 *2.2 将要被唤醒的线程加入唤醒队列，并从等待队列中删除掉；
 */
SEC("kprobe/futex_wake_mark")
int BPF_KPROBE(trace_futex_wake_mark, struct wake_q_head *wake_q, struct futex_q *q) 
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) 
        return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    
    if(mfutex_ctrl->target_pid == -1 && mfutex_ctrl->target_tgid == -1)//未指定目标进程或线程
        return 0;
    if((mfutex_ctrl->target_pid != -1 && pid!=mfutex_ctrl->target_pid)||
        (mfutex_ctrl->target_tgid != -1 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
        return 0;

    u64 *lock_ptr;
    u64 temp_lock_ptr;
    u64 ts = bpf_ktime_get_ns();

    /*1.找到锁的地址*/
    struct proc_flag proc_flag = {};
    proc_flag.pid = pid;
    proc_flag.flag = FUTEX_FLAG;
    lock_ptr = bpf_map_lookup_elem(&proc_unlock, &proc_flag);
    if(!lock_ptr) return 0;
    temp_lock_ptr = *lock_ptr;

    /*2.make key*/
    struct lock_record_key key = {};
    key.lock_ptr = temp_lock_ptr;
    key.pid = BPF_CORE_READ(q,task,pid);

    /*3.将线程从等待队列中删除*/
    struct per_request *per_request;
    per_request = bpf_map_lookup_elem(&futex_wait_queue, &key);
    if(per_request) {//如果等待队列中找到该task 则尝试删除
        bpf_map_delete_elem(&futex_wait_queue, &key);
        per_request->start_hold_time = ts;
        per_request->wait_delay = ts - per_request->start_hold_time;
    }else{//如果没找到，说明该任务陷入阻塞时未记录，则创建per_request
        struct per_request new_per_request = {};
        new_per_request.pid = key.pid;
        new_per_request.start_hold_time = ts;
        per_request = &new_per_request;
    }
    /*4.将任务放到唤醒队列中*/
    bpf_map_update_elem(&futex_wake_queue, &key, per_request, BPF_ANY);
    return 0;
}

/*2.将线程加入唤醒队列，从等待队列中删除
 *2.1 将执行futex_wake的线程pid与锁地址进行匹配，便于在后面futex_wake_mark找到锁地址
 */
SEC("kretprobe/futex_wake")
int BPF_KRETPROBE(trace_futex_wake_exit) 
{
    struct mfutex_ctrl *mfutex_ctrl = get_mfutex_ctrl();
    if(!mfutex_ctrl) 
        return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int tgid = bpf_get_current_pid_tgid() >> 32;
    
    if(mfutex_ctrl->target_pid == -1 && mfutex_ctrl->target_tgid == -1)//未指定目标进程或线程
        return 0;
    if((mfutex_ctrl->target_pid != -1 && pid!=mfutex_ctrl->target_pid)||
        (mfutex_ctrl->target_tgid != -1 && tgid != mfutex_ctrl->target_tgid))//当前进程或线程非目标进程或线程
        return 0;

    u64 *lock_ptr;
    u64 temp_lock_ptr;
    u64 ts = bpf_ktime_get_ns();

    /*1.找到锁的地址*/
    struct proc_flag proc_flag = {};
    proc_flag.pid = pid;
    proc_flag.flag = FUTEX_FLAG;
    lock_ptr = bpf_map_lookup_elem(&proc_unlock, &proc_flag);
    if(!lock_ptr) return 0;
    temp_lock_ptr = *lock_ptr;
    bpf_map_delete_elem(&proc_unlock, &proc_flag);

    /*2.传入rb*/
    struct per_lock_event *e;
    e = bpf_ringbuf_reserve(&mfutex_rb, sizeof(*e), 0);
    if(!e)
        return 0;
    e->lock_ptr = temp_lock_ptr;
    e->start_hold_time = bpf_ktime_get_ns();
    e->type = FUTEX_FLAG;
    bpf_ringbuf_submit(e, 0);
    return 0;   
}