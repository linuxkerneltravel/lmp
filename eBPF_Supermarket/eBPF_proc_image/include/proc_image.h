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

#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
    /* type：
        1代表on_cpu；2代表off_cpu；
        3代表exec_enter；4代表exec_exit；5代表exit
        6代表umutex_req；7代表umutex_lock；8代表umutex_unlock
        9代表kmutex_req；10代表kmutex_lock；11代表kmutex_unlock
        12代表rdlock_req；13代表rdlock_lock；14代表rdlock_unlock
        15代表wrlock_req；16代表wrlock_lock；17代表wrlock_unlock
        18代表fork_begin；19代表fork_end
        20代表vfork_begin；21代表vfork_end
        22代表pthread_begin；23代表pthread_end
    */
	int type;
	pid_t pid;
	pid_t ppid;
    int cpu_id;
	char comm[TASK_COMM_LEN];
	long long unsigned int start;
	long long unsigned int exit;
	int retval;
	bool enable_char_args;
	int args_count;
	long long unsigned int ctx_args[6];
	unsigned int args_size;
	char args[FULL_MAX_ARGS_ARR];
};

#endif /* __PROC_IMAGE_H */