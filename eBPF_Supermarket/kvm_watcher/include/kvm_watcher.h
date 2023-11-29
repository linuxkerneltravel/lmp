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
// author: nanshuaibo811@163.com
//
// BPF program used for monitoring KVM event.

#ifndef __KVM_WATCHER_H
#define __KVM_WATCHER_H

#define TASK_COMM_LEN	 16

struct process{
	unsigned pid;
	unsigned tid;
	char comm[TASK_COMM_LEN];
};
struct vcpu_wakeup_event {
	struct process process;
	unsigned long long dur_hlt_ns;
	bool waited;
	unsigned long long hlt_time;
};

struct exit_event {
	struct process process;
	unsigned reason_number;
	unsigned long long duration_ns;
	int count;
	int total;
};

struct ExitReason {
	int number;
	const char* name;
};

struct reason_info {
	unsigned long long time;
	unsigned long  reason;
	int count;
};

#endif /* __KVM_WATCHER_H */