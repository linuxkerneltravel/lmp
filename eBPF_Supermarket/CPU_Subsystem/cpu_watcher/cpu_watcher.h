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
// eBPF map for libbpf sar

typedef long long unsigned int u64;
typedef unsigned int u32;

/*----------------------------------------------*/
/*          cs_delay结构体                     */
/*----------------------------------------------*/
#ifndef __CS_DELAY_H
#define __CS_DELAY_H
struct event {
	long unsigned int t1;
	long unsigned int t2;
	long unsigned int delay;
};
#endif /* __CS_DELAY_H */

/*----------------------------------------------*/
/*          cswch_args结构体                     */
/*----------------------------------------------*/
struct cswch_args {
	u64 pad;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
};

/*----------------------------------------------*/
/*          软中断结构体                         */
/*----------------------------------------------*/
struct __softirq_info {
	u64 pad;
	u32 vec;
};

/*----------------------------------------------*/
/*          硬中断结构体                         */
/*----------------------------------------------*/
struct __irq_info {
	u64 pad;
	u32 irq;
};

/*----------------------------------------------*/
/*          idlecpu空闲时间所需结构体             */
/*----------------------------------------------*/
struct idleStruct {
	u64 pad;
	int state;
	u32 cpu_id;
};




