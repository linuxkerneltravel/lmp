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
// eBPF map for the process key time image

#ifndef __KEYTIME_IMAGE_H
#define __KEYTIME_IMAGE_H

#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
	int flag;		// 1代表execve_enter；2代表execve_exit；3代表exit
	pid_t pid;
	pid_t ppid;
	char comm[TASK_COMM_LEN];
	long long unsigned int start;
	long long unsigned int exit;
	int retval;
	bool enable_char_args;
	int args_count;
	long unsigned int ctx_args[6];
	unsigned int args_size;
	char args[FULL_MAX_ARGS_ARR];
};

#endif /* __KEYTIME_IMAGE_H */
