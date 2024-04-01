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
// author: GaoYiXiang
//
// 内核态bpf程序的模板代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "bpf_wapper/bio.h"
#include "task.h"

COMMON_MAPS(struct internal_rqinfo);
COMMON_VALS;
BPF_HASH(requests, struct request * , psid);

const volatile int apid = 0;
// const volatile bool filter_dev = false;
// const volatile __u32 targ_dev = -1;

struct request_queue___x {
	struct gendisk *disk;
} __attribute__((preserve_access_index));
struct request___x {
	struct request_queue___x *q;
	struct gendisk *rq_disk;
} __attribute__((preserve_access_index));
static __always_inline struct gendisk *get_disk(void *request)
{
	struct request___x *r = request;

	if (bpf_core_field_exists(r->rq_disk))
		return BPF_CORE_READ(r, rq_disk);
	return BPF_CORE_READ(r, q, disk);
}


static __always_inline int trace_start(void *ctx, struct request *rq, bool merge_bio)
{
    // 获取请求相关联的块设备
    struct internal_rqinfo *i_rqinfop = NULL, i_rqinfo = {};
	struct gendisk *disk = get_disk(rq);
	u32 dev;

    //进程task_struct
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task(); // 利用bpf_get_current_task()获得当前的进程tsk
    RET_IF_KERN(curr);

    u32 pid = get_task_ns_pid(curr); // 利用帮助函数获得当前进程的pid
    if ((apid >= 0 && pid != apid) || !pid || pid == self_pid)
        return 0;

    SAVE_TASK_INFO(pid, curr);
    psid apsid = GET_COUNT_KEY(pid, ctx);

    //存储request对应的psid
    bpf_map_update_elem(&requests , &rq, &apsid, BPF_ANY);

    dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
			BPF_CORE_READ(disk, first_minor)) : 0;


	if (merge_bio){
        //查找rq对应的psid,如果没有找到，则要先初始化这个表
        psid *bpsid = bpf_map_lookup_elem(&requests,&rq);
        if(!bpsid)
            return 0;
        i_rqinfop = bpf_map_lookup_elem(&psid_count_map, bpsid);
    }
	if (!i_rqinfop)
		i_rqinfop = &i_rqinfo;
    i_rqinfop->start_ts = bpf_ktime_get_ns();
	i_rqinfop->rqinfo.pid = bpf_get_current_pid_tgid();
	i_rqinfop->rqinfo.kern_stack_size =
		bpf_get_stack(ctx, i_rqinfop->rqinfo.kern_stack,
			sizeof(i_rqinfop->rqinfo.kern_stack), 0);
	bpf_get_current_comm(&i_rqinfop->rqinfo.comm,
			sizeof(&i_rqinfop->rqinfo.comm));
	i_rqinfop->rqinfo.dev = dev;

	if (i_rqinfop == &i_rqinfo){
        psid *bpsid = bpf_map_lookup_elem(&requests,&rq);
        if(!bpsid)
            return 0;
        bpf_map_update_elem(&psid_count_map, bpsid, &i_rqinfo, 0);
    }

    return 0;
}

SEC("kprobe/blk_account_io_merge_bio")
int BPF_KPROBE(blk_account_io_merge_bio, struct request *rq)
{
    return trace_start(ctx, rq, true);
}

SEC("tp_btf/block_io_start")
int BPF_PROG(block_io_start, struct request *rq)
{
    return trace_start(ctx, rq, false);
}


char LICENSE[] SEC("license") = "GPL";
