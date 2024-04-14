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
// eBPF map for the process image

#ifndef __PROC_IMAGE_H
#define __PROC_IMAGE_H

#define MAX_SYSCALL_COUNT 50
#define ARGSIZE  128
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR 440
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

#define TASK_RUNNING	0x00000000

#define MAX_STACK_DEPTH 128
typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

// resource_image
struct rsc_ctrl{
	bool rsc_func;
	pid_t target_pid;
	int target_cpu_id;
	bool enable_myproc;
	pid_t target_tgid;
};

struct proc_id{
	int pid;
	int cpu_id;
}; 

struct start_rsc{
	long long unsigned int time;
	long long unsigned int readchar;
	long long unsigned int writechar;
};

struct total_rsc{
    int pid;
	int tgid;
	int cpu_id;
	long long unsigned int time;
	long unsigned int memused;
	long long unsigned int readchar;
	long long unsigned int writechar;
};

//syscall_image
struct sc_ctrl {
    bool sc_func;
    bool enable_myproc;
    pid_t target_pid;
    pid_t target_tgid;
    int syscalls;
};

struct syscall_seq{
	int pid;
	int tgid;
	long long unsigned int enter_time;
	long long unsigned int sum_delay;
	long long unsigned int proc_sd;
	long long unsigned int max_delay;
	long long unsigned int min_delay;
	unsigned int count;
	unsigned int proc_count;
	int record_syscall[MAX_SYSCALL_COUNT];
};

// lock_image
struct lock_ctrl{
    bool lock_func;
    bool enable_myproc;
	pid_t target_pid;
	pid_t target_tgid;
};

struct proc_flag{
    int pid;
    // 1代表用户态互斥锁
    // 2代表用户态读写锁
	// 3代表用户态自旋锁
    int flag;
};

struct lock_event{
    /* lock_status：
        1代表mutex_req；2代表mutex_lock；3代表mutex_unlock
        4代表rdlock_req；5代表rdlock_lock；6代表rdlock_unlock
        7代表wrlock_req；8代表wrlock_lock；9代表wrlock_unlock
		10代表spinlock_req；11代表spinlock_lock；12代表spinlock_unlock
    */
    int lock_status;
    int pid;
	int tgid;
	int ret;
    long long unsigned int lock_ptr;
    long long unsigned int time;
};

// keytime_image
struct kt_ctrl{
	bool kt_func;
	bool kt_cpu_func;
	bool enable_myproc;
	pid_t target_pid;
	pid_t target_tgid;
};

struct child_info{
	int type;
	int ppid;
	int ptgid;
};

struct keytime_event{
	/* type:
		1代表exec_enter；2代表exec_exit
		3代表exit
		4代表forkP_enter；5代表forkP_exit
		6代表vforkP_enter；7代表vforkP_exit
		8代表createT_enter；9代表createT_exit
		10代表onCPU；11代表offCPU(事件用offcpu_event结构体表示)
	*/
	int type;
	int pid;
	int tgid;
	bool enable_char_info;
	int info_count;
	long long unsigned int info[6];
	unsigned int info_size;
	char char_info[FULL_MAX_ARGS_ARR];
};

// offCPU
struct offcpu_event{
	// 为固定值 11，为了标识 offCPU事件
	int type;
	int pid;
	int tgid;
	long long unsigned int offcpu_time;
	__s32 kstack_sz;
	stack_trace_t kstack;
};

// schedule_image
struct sched_ctrl {
    bool sched_func;
    pid_t target_pid;
    int target_cpu_id;
    int target_tgid;
};

struct schedule_event{
	int pid;
	int tgid;
	int prio;
	int count;
	long long unsigned int enter_time;
	long long unsigned int sum_delay;
	long long unsigned int max_delay;
	long long unsigned int min_delay;
};

struct sum_schedule{
	long long unsigned int sum_count;
	long long unsigned int sum_delay;
	long long unsigned int max_delay;
	long long unsigned int min_delay;
};

#endif /* __PROCESS_H */