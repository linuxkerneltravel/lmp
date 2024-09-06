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
    if(!redis_info) return 0;
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
    if(!redis_info) return 0;
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
static __always_inline int __handle_redis_key(struct pt_regs *ctx) {
    if(!redis_stat) return 0;
    robj *key_obj = (robj *)PT_REGS_PARM2(ctx);
    char redis_key[256];
    u32 *count;
    u32 initial_count = 1;

    if (!key_obj)
        return 0;

    robj local_key_obj;
    if (bpf_probe_read_user(&local_key_obj, sizeof(local_key_obj), key_obj) != 0) {
        bpf_printk("Failed to read local_key_obj\n");
        return 0;
    }

    if (!local_key_obj.ptr) {
        bpf_printk("local_key_obj.ptr is null\n");
        return 0;
    }

    int ret;
    ret = bpf_probe_read_user_str(redis_key, sizeof(redis_key), local_key_obj.ptr);
    if (ret <= 0) {
        bpf_printk("Read string failed: %d\n", ret);
        return 0;
    }

    // 打印读取到的键值
    bpf_printk("Read key: %s\n", redis_key);

    // 查找或更新键的计数
    count = bpf_map_lookup_elem(&key_count, redis_key);
    if (count) {
        //bpf_printk("Found key, incrementing count\n");
        // 如果已经存在，增加计数值
        (*count)++;
        bpf_map_update_elem(&key_count, redis_key, count, BPF_ANY);
    } else {
        //bpf_printk("Key not found, initializing count\n");
        // 如果不存在，初始化计数值为 1
        bpf_map_update_elem(&key_count, redis_key, &initial_count, BPF_ANY);
    }

    // 打印调试信息
    struct redis_stat_query *message = bpf_ringbuf_reserve(&redis_stat_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->pid=bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&message->comm, sizeof(message->comm));
    memcpy(message->key, redis_key, sizeof(message->key));
    message->key_count=count ? *count : initial_count;
    message->value_type=0;
    memset(message->value, 0, sizeof(message->value));
    bpf_printk("Key: %s\n", message->key);
    bpf_printk("Count: %d\n", message->key_count);
    bpf_ringbuf_submit(message, 0);
    
    return 0;
}
static __always_inline int __handle_redis_value(struct pt_regs *ctx) {
    if(!redis_stat) return 0;
    robj *key_obj = (robj *)PT_REGS_PARM2(ctx);
    int ret;
    char redis_value[64];
    if (!key_obj)
        return 0;
    robj local_key_obj;
    if (bpf_probe_read_user(&local_key_obj, sizeof(local_key_obj), key_obj) != 0) {
        bpf_printk("Failed to read local_key_obj\n");
        return 0;
    }
    if (!local_key_obj.ptr) {
        bpf_printk("local_key_obj.ptr is null\n");
        return 0;
    }
    ret = bpf_probe_read_user_str(redis_value, sizeof(redis_value), local_key_obj.ptr);
    if (ret <= 0) {
        bpf_printk("Read string failed: %d\n", ret);
        return 0;
    }
    struct redis_stat_query *message = bpf_ringbuf_reserve(&redis_stat_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->pid=bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&message->comm, sizeof(message->comm));
    memset(message->key, 0, sizeof(message->key));
    message->key_count=0;
    message->value_type=local_key_obj.type;
    memcpy(message->value, redis_value, sizeof(message->value));
    bpf_printk("Value: %s\n", message->value);
    bpf_printk("type: %d\n", message->value_type);
    bpf_ringbuf_submit(message, 0);
    return 0;   
}