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
// author: luiyanbing@foxmail.com
//
// 内核态bpf的io-cpu模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_analyzer.h"
#include "task.h"


                                                                    //定义的哈希表以及堆栈跟踪对象
BPF_HASH(psid_count, psid, u64);
BPF_STACK_TRACE(stack_trace);                                       //记录了相应的函数内核栈以及用户栈的使用次数
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

const char LICENSE[] SEC("license") = "GPL";

int apid = 0;
bool u = false, k = false, cot = false;
__u64 min = 0, max = 0;

static int do_stack(struct trace_event_raw_sys_enter *ctx)
{
    // u64 td = bpf_get_current_pid_tgid();
    // u32 pid = td >> 32;

    struct task_struct* curr = (struct task_struct*)bpf_get_current_task();//利用bpf_get_current_task()获得当前的进程tsk
    u32 pid = get_task_ns_pid(curr);                                    //利用帮助函数获得当前进程的pid

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    u64 len = (u64)BPF_CORE_READ(ctx, args[3]);                         //从当前ctx中读取64位的值，并保存在len中，
    if (len <= min || len > max)
        return 0;

    // u32 tgid = td;
    u32 tgid = get_task_ns_tgid(curr);                                  //利用帮助函数获取进程的tgid
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);               //将pid_tgid表中的pid选项更新为tgid,若没有该表项，则创建
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);                     //p指向pid_comm哈希表中的pid表项对应的value
    if (!p)                                                             //如果p不为空，获取当前进程名保存至name中，如果pid_comm当中不存在pid name项，则更新
    {
        comm name;
        bpf_get_current_comm(&name, COMM_LEN);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
    }
    psid apsid = {
        .pid = pid,
         .usid = u ? USER_STACK : -1,                                                   //u存在，则USER_STACK
        .ksid = k ? KERNEL_STACK : -1,                                                   //K存在，则KERNEL_STACK
    };

    // record time delta
    u64 *count = bpf_map_lookup_elem(&psid_count, &apsid);                          //count指向psid_count表当中的apsid表项，即size
    if (cot)
    {
        if (count)                                                                  //如果count不为NULL，则对count指向的值+1
            (*count)++;
        else
        {
            u64 one = 1;                                                            //当psid_count中不存在apsid，就更新表项中的apsid=1
            bpf_map_update_elem(&psid_count, &apsid, &one, BPF_NOEXIST);
        }
    }
   else                                                                             //cot=false
    {
        if (count)                                                                  //如果count不为NULL，则对count指向的值+len
            (*count) += len;
        else
                                             
            bpf_map_update_elem(&psid_count, &apsid, &len, BPF_NOEXIST);            //当psid_count中不存在apsid，就更新表项中的apsid=len
    }
    return 0;
}

#define io_sec_tp(name)                         \
    SEC("tracepoint/syscalls/sys_enter_" #name) \
    int prog_t_##name(struct trace_event_raw_sys_enter *ctx) { return do_stack(ctx); }

// tracepoint:syscalls:sys_exit_select
// tracepoint:syscalls:sys_enter_poll
// tracepoint:syscalls:sys_enter_epoll_wait


// 1. 设置挂载点
// tracepoint/syscalls/sys_enter_write 读操作
// tracepoint/syscalls/sys_enter_read 写操作
// tracepoint/syscalls/sys_enter_recvfrom 接收数据
// tracepoint/syscalls/sys_enter_sendto 发送数据

//2. 执行程序 int prog_t_##name(struct trace_event_raw_sys_enter *ctx) { return do_stack(ctx); }
//最终调用上面的do_stack函数

io_sec_tp(write);
io_sec_tp(read);
io_sec_tp(recvfrom);
io_sec_tp(sendto);
