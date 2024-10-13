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
    enum enum_server_command command = PT_REGS_PARM3(ctx);
    union COM_DATA *com_data = (union COM_DATA *)PT_REGS_PARM2(ctx);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();
    void *thd = (void *)PT_REGS_PARM1(ctx);
    struct query_info info;
    u32 size = 0;
    char *sql;

    bpf_probe_read(&info.size, sizeof(info.size), &com_data->com_query.length);
    bpf_probe_read(&sql, sizeof(sql), &com_data->com_query.query);
    bpf_probe_read(&info.msql, sizeof(info.msql), sql);
    // bpf_printk("sql1==%s size1==%lu", sql,info.size);
    info.start_time = bpf_ktime_get_ns() / 1000;

    bpf_map_update_elem(&queries, &tid, &info, BPF_ANY);
    return 0;
}

static __always_inline int __handle_mysql_end(struct pt_regs *ctx) {
    char comm[16];
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t tid = bpf_get_current_pid_tgid();
    struct query_info *info = bpf_map_lookup_elem(&queries, &tid);
    if (!info) {
        return 0;
    }

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
    message->duratime = bpf_ktime_get_ns() / 1000 - info->start_time;
    message->pid = pid;
    message->tid = tid;
    bpf_get_current_comm(&message->comm, sizeof(comm));
    message->size = info->size;
    bpf_probe_read_str(&message->msql, sizeof(message->msql), info->msql);

    bpf_ringbuf_submit(message, 0);
    return 0;
}
