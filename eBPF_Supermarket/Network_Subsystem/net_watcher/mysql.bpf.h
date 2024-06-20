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
// mysql

#include "common.bpf.h"
#include "mysql_helper.bpf.h"
static __always_inline int __handle_mysql_start(struct pt_regs *ctx) {
    // dispatch_command(THD *thd, const COM_DATA *com_data, enum
    char comm[16];
    enum enum_server_command command = PT_REGS_PARM3(ctx);
    union COM_DATA *com_data = (union COM_DATA *)PT_REGS_PARM2(ctx);

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();
    void *thd = (void *)PT_REGS_PARM1(ctx);
    char *sql;
    u32 size = 0;

    if (command != COM_QUERY) {
        return 0;
    }

    u64 start_time = bpf_ktime_get_ns() / 1000;
    bpf_map_update_elem(&mysql_time, &pid, &start_time, BPF_ANY);

    struct mysql_query *message =
        bpf_ringbuf_reserve(&mysql_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }

    bpf_probe_read(&message->size, sizeof(message->size),
                   &com_data->com_query.length);
    bpf_probe_read_str(&sql, sizeof(sql), &com_data->com_query.query);
    bpf_probe_read_str(&message->msql, sizeof(message->msql), sql);

    message->pid = pid;
    message->tid = tid;
    bpf_get_current_comm(&message->comm, sizeof(comm));
    
    bpf_ringbuf_submit(message, 0);

    return 0;
}

static __always_inline int __handle_mysql_end(struct pt_regs *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();
    u64 *start_time_ptr, duration;
    u64 end_time = bpf_ktime_get_ns() / 1000;
    start_time_ptr = bpf_map_lookup_elem(&mysql_time, &pid);
    if (!start_time_ptr) {
        return 0;
    }

    duration = end_time - *start_time_ptr;
    struct mysql_query *message =
        bpf_ringbuf_reserve(&mysql_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    u64 *count_ptr, count = 1;
    count_ptr = bpf_map_lookup_elem(&sql_count, &tid);
    if (count_ptr) {
        count = *count_ptr + 1;
    }
    message->count = count;
    bpf_map_update_elem(&sql_count, &tid, &count, BPF_ANY);

    message->duratime = duration;

    bpf_ringbuf_submit(message, 0);
    bpf_map_delete_elem(&mysql_time, &pid);

    return 0;
}
