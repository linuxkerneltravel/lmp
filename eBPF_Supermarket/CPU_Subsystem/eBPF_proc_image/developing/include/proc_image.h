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

#define MAX_SYSCALL_COUNT 116

// resource_image
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
	int cpu_id;
	long long unsigned int time;
	long unsigned int memused;
	long long unsigned int readchar;
	long long unsigned int writechar;
};

//syscall_image
struct syscall_seq{
	int pid;
	long long unsigned int oncpu_time;
	long long unsigned int offcpu_time;
	int count;		// 若count值超过MAX_SYSCALL_COUNT，则record_syscall数组最后一个元素的值用-1表示以作说明
	int record_syscall[MAX_SYSCALL_COUNT];
};

// lock_image
struct proc_flag{
    int pid;
    // 1代表用户态互斥锁
    // 2代表用户态读写锁
    int flag;
};

struct lock_event{
    /* lock_status：
        1代表mutex_req；2代表mutex_lock；3代表mutex_unlock
        4代表rdlock_req；5代表rdlock_lock；6代表rdlock_unlock
        7代表wrlock_req；8代表wrlock_lock；9代表wrlock_unlock
    */
    int lock_status;
    int pid;
	int ret;
    long long unsigned int lock_ptr;
    long long unsigned int time;
};

#endif /* __PROCESS_H */