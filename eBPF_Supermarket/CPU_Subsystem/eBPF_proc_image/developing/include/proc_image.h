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

#define MAX_SYSCALL_COUNT 58
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)

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
	long int record_syscall[MAX_SYSCALL_COUNT];
};

#endif /* __PROCESS_H */