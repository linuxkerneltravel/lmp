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
// author: blown.away@qq.com
// redis

#include "common.bpf.h"
#include "redis_helper.bpf.h"
#define MAXEPOLL 5
static __always_inline int __handle_redis_start(struct pt_regs *ctx) {
    struct client *cli = (struct client *)PT_REGS_PARM1(ctx);
    struct redis_query start={};
    void *ptr;             
    char name[100]=""; 
    int argv_len;          
    bpf_probe_read(&start.argc, sizeof(start.argc), &cli->argc);
    robj **arg0;
    robj *arg1;
    bpf_probe_read(&arg0, sizeof(arg0), &cli->argv);
    bpf_probe_read(&arg1, sizeof(arg1), &arg0[0]);
    for(int i=0;i<start.argc&&i<MAXEPOLL;i++)
    {    
        bpf_probe_read(&arg1, sizeof(arg1), &arg0[i]);
        bpf_probe_read(&ptr, sizeof(ptr),&arg1->ptr);
        bpf_probe_read_str(&start.redis[i], sizeof(start.redis[i]), ptr);
    }
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 start_time = bpf_ktime_get_ns() / 1000;
    start.begin_time=start_time;
    bpf_map_update_elem(&redis_time, &pid, &start, BPF_ANY);
    return 0;
}

static __always_inline int __handle_redis_end(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct redis_query *start;
    u64 end_time = bpf_ktime_get_ns() / 1000;
    start = bpf_map_lookup_elem(&redis_time, &pid);
    if (!start) {
        return 0;
    }
    struct redis_query *message = bpf_ringbuf_reserve(&redis_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->pid = pid;
    message->argc = start->argc;
    bpf_get_current_comm(&message->comm, sizeof(message->comm));
    for(int i=0;i<start->argc&&i<MAXEPOLL;i++)
    {    
        bpf_probe_read_str(&message->redis[i], sizeof(message->redis[i]), start->redis[i]);
    }
    bpf_probe_read_str(&message->redis, sizeof(start->redis), start->redis);
    message->duratime = end_time - start->begin_time;
    bpf_ringbuf_submit(message, 0);
    return 0;
}