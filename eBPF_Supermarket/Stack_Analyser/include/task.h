// Copyright 2019 Aqua Security Software Ltd.
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
// This product includes software developed by Aqua Security (https://aquasec.com).

#ifndef __COMMON_TASK_H__
#define __COMMON_TASK_H__

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>

#define statfunc static __always_inline

struct pid_link
{
    struct hlist_node node;
    struct pid *pid;
};

struct task_struct___older_v50
{
    struct pid_link pids[PIDTYPE_MAX];
};

statfunc u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    if (bpf_core_type_exists(struct pid_link))
    {
        struct task_struct___older_v50 *t = (void *)task;
        pid = BPF_CORE_READ(t, pids[PIDTYPE_PID].pid);
    }
    else
    {
        pid = BPF_CORE_READ(task, thread_pid);
    }

    level = BPF_CORE_READ(pid, level);

    return BPF_CORE_READ(pid, numbers[level].nr);
}

statfunc u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

statfunc u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    return get_task_pid_vnr(group_leader);
}

statfunc u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    return get_task_pid_vnr(real_parent);
}

static void fill_container_id(struct kernfs_node *knode, char *container_id)
{
    if (BPF_CORE_READ(knode, parent) != NULL)
    {
        char *aus;
        bpf_probe_read(&aus, sizeof(void *), &(knode->name));
        bpf_probe_read_str(container_id, CONTAINER_ID_LEN, aus);
    }
}

#endif