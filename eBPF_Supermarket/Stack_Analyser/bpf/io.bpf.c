// Copyright 2024 The LMP Authors.
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
// author: luiyanbing@foxmail.com
//
// 内核态bpf的io-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "bpf_wapper/io.h"
#include "task.h"

DeclareCommonMaps(io_tuple);
DeclareCommonVar();
const volatile int apid = 0;

const char LICENSE[] SEC("license") = "GPL";

static int do_stack(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task(); // 利用bpf_get_current_task()获得当前的进程tsk
    ignoreKthread(curr);
    u32 pid = get_task_ns_pid(curr); // 利用帮助函数获得当前进程的pid
    if ((apid >= 0 && pid != apid) || !pid || pid == self_pid)
        return 0;
    u64 len = BPF_CORE_READ(ctx, args[2]); // 读取系统调用的第三个参数
    if (len <= min || len > max)
        return 0;
    if (!bpf_map_lookup_elem(&pid_info, &pid))
    {
        task_info info;
        info.tgid = get_task_ns_tgid(curr);
        bpf_get_current_comm(info.comm, COMM_LEN);
        fill_container_id(curr, info.cid);
        bpf_map_update_elem(&pid_info, &pid, &info, BPF_NOEXIST);
    }
    psid apsid = {
        .pid = pid,
        .usid = trace_user ? USER_STACK : -1,     // u存在，则USER_STACK
        .ksid = trace_kernel ? KERNEL_STACK : -1, // K存在，则KERNEL_STACK
    };

    // record time delta
    io_tuple *d = bpf_map_lookup_elem(&psid_count, &apsid); // count指向psid_count表当中的apsid表项，即size

    if (!d)
    {
        io_tuple nd = {.count = 1, .size = len};
        bpf_map_update_elem(&psid_count, &apsid, &nd, BPF_NOEXIST);
    }
    else
    {
        d->count++;
        d->size += len;
    }
    return 0;
}

#define io_sec_tp(name)                 \
    SEC("tp/syscalls/sys_enter_" #name) \
    int prog_t_##name(struct trace_event_raw_sys_enter *ctx) { return do_stack(ctx); }

io_sec_tp(write);
io_sec_tp(read);
io_sec_tp(recvfrom);
io_sec_tp(sendto);

// tracepoint:syscalls:sys_exit_select
// tracepoint:syscalls:sys_enter_poll
// tracepoint:syscalls:sys_enter_epoll_wait

// 1. 设置挂载点
// tracepoint/syscalls/sys_enter_write 读操作
// tracepoint/syscalls/sys_enter_read 写操作
// tracepoint/syscalls/sys_enter_recvfrom 接收数据
// tracepoint/syscalls/sys_enter_sendto 发送数据

// 2. 执行程序 int prog_t_##name(struct trace_event_raw_sys_enter *ctx) { return do_stack(ctx); }
// 最终调用上面的do_stack函数