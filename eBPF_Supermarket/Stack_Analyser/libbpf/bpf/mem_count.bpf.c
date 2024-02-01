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
// 内核态ebpf的内存模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sa_ebpf.h"
#include "task.h"

//定义的哈希表以及堆栈跟踪对象
DeclareCommonMaps(u64);
DeclareCommonVar();

/// @brief 内存信息的键，唯一标识一块被分配的内存
/// @note o为可初始化的填充对齐成员，贴合bpf verifier要求
typedef struct {
    __u64 addr;
    __u32 pid, o;
} piddr;

/// @brief 内存分配信息，可溯源的一次内存分配
/// @note o为可初始化的填充对齐成员，贴合bpf verifier要求
typedef struct {
    __u64 size;
    __u32 usid, o;
} mem_info;

BPF_HASH(pid_size, u32, u64);                                           //记录了对应进程使用malloc,calloc等函数申请内存的大小
BPF_HASH(piddr_meminfo, piddr, mem_info);                               //记录了每次申请的内存空间的起始地址等信息

const char LICENSE[] SEC("license") = "GPL";

int gen_alloc_enter(size_t size)
{
    if (size <= min || size > max)
        return 0;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();    //利用bpf_get_current_task()获得当前的进程tsk
    ignoreKthread(curr);
    u32 pid = get_task_ns_pid(curr); // also kernel pid, but attached ns pid on kernel pid, invaild!
    if(pid == self_pid)
        return 0;
    u32 tgid = get_task_ns_tgid(curr);                                          //利用帮助函数获得当前进程的tgid
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);                       //更新pid_tgid哈希表中的pid项目为tgid,如果该项不存在，则创建该表项
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);                             //p指向pid_comm哈希表中的pid表项对应的value
    
    if (!p)                                                                     //如果p不为空，获取当前进程名保存至name中，如果pid_comm当中不存在pid => name项，则更新
    {
        comm name;
        bpf_get_current_comm(&name, COMM_LEN);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
    }

    // record size
    //size为挂载点传递的值
    return bpf_map_update_elem(&pid_size, &pid, &size, BPF_ANY);                //更新pid_size哈希表的pid项对应的值为size，如果不存在该项，则创建
}


SEC("uprobe/malloc")                                                            //用户空间探针uprobe,挂载点为malloc函数
int BPF_KPROBE(malloc_enter, size_t size)
{
    return gen_alloc_enter(size);                                             //当用户程序执行到malloc函数，则执行gen_alloc_enter（size）
}


SEC("uprobe/calloc")                                                         //用户空间探针uprobe,挂载点为calloc函数
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
    return gen_alloc_enter(nmemb * size);                                   //当用户程序执行到calloc函数，则执行gen_alloc_enter（size）
}


SEC("uprobe/mmap")                                                          //用户空间探针uprobe,挂载点为mmap函数
int BPF_KPROBE(mmap_enter)
{
    size_t size = PT_REGS_PARM2(ctx);                                       //size为该函数的第二个参数的值
    return gen_alloc_enter(size);                                           //当用户程序执行到mmap函数，则执行gen_alloc_enter（size）
}

int gen_alloc_exit(struct pt_regs *ctx)                                     //传入的参数ctx是个pt_regs（定义在vmlinux.h）的指针
{
    void *addr = (void *)PT_REGS_RC(ctx);                                   //从 struct pt_regs ctx 中提取函数的返回值
    if (!addr)
        return 0;
    u32 pid = get_task_ns_pid((struct task_struct*)bpf_get_current_task());//通过bpf_get_current_task函数得到当前进程的tsk。再通过get_task_ns_pid得到该进程的pid
    u64 *size = bpf_map_lookup_elem(&pid_size, &pid);                       //size指向pid_size哈希表pid对应的值
    if (!size)                                                              //size不存在
        return -1;

    // record stack count
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = k ? KERNEL_STACK: -1,
    };
    u64 *count = bpf_map_lookup_elem(&psid_count, &apsid);  //count指向psid_count表apsid对应的值

    if (!count)                                             //如果count为空，若表的apsid表项不存在，则更新psid_count表的apsid为size
        bpf_map_update_elem(&psid_count, &apsid, size, BPF_NOEXIST);
    else
        (*count) += *size;                                  //psid_count表apsid对应的值+=pid_size哈希表pid对应的值

    // record pid_addr-info
    piddr a = {
        .addr = (u64)addr,                                  //函数的返回值
        .pid = pid,
        .o = 0,
    };
    mem_info info = {
        .size = *size,
        .usid = apsid.usid,                                 //表示是在用户空间，因此设为用户栈
        .o = 0,
    };
           
    return bpf_map_update_elem(&piddr_meminfo, &a, &info, BPF_NOEXIST);//如果表中不存在a这个表项，则更新piddr_meminfo表的a对应的值为info
}


SEC("uretprobe/malloc")                                             //用户空间探针uretprobe,挂载点为malloc函数
int BPF_KRETPROBE(malloc_exit)
{
    return gen_alloc_exit(ctx);                                     //当用户程序退出malloc函数，则执行gen_alloc_exit（ctx）
}


SEC("uretprobe/calloc")                                             //用户空间探针uretprobe,挂载点为calloc函数
int BPF_KRETPROBE(calloc_exit)
{
    return gen_alloc_exit(ctx);                                     //当用户程序退出clloc函数，则执行gen_alloc_exit（ctx）
}

SEC("uretprobe/realloc")                                            //用户空间探针uretprobe,挂载点为realloc函数
int BPF_KRETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);                                     //当用户程序退出realloc函数，则执行gen_alloc_exit（ctx）
}


SEC("uretprobe/mmap")                                               //用户空间探针uretprobe,挂载点为mmap函数
int BPF_KRETPROBE(mmap_exit)
{
    return gen_alloc_exit(ctx);                                     //当用户程序退出mmap函数，则执行gen_alloc_exit（ctx）
}

int gen_free_enter(u64 addr, size_t unsize)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;                     //获取当前进程的pid
    // struct task_struct* curr = (struct task_struct*)bpf_get_current_task();
    // u32 pid = get_task_ns_pid(curr);
    piddr a = {.addr = addr, .pid = pid, .o = 0};
    mem_info *info = bpf_map_lookup_elem(&piddr_meminfo, &a);       //info指向piddr_meminfo表中的a的值
    if (!info)
        return -1;

    // get allocated size
    psid apsid = {
        .ksid = -1,
        .pid = pid,
        .usid = info->usid,
    };
    
    u64 *size = bpf_map_lookup_elem(&psid_count, &apsid);               //size指向psid_count中apsid对应的值，即对应pid的总空间大小
    if (!size)
        return -1;

    // sub the freeing size
                                                                     //unsize为传入的值,是代表释放的空间大小
    if(unsize) {
      
        if (unsize >= *size)                                        //unsize>=psid_count中apsid对应的值
            *size = 0;                                              //psid_count中apsid对应的值 = 0
        else
            (*size) -= unsize;                                   //否则，psid_count中apsid对应的值-=unsize
    }
    else
        (*size) -= info->size;                                  //unsize=0，则psid_count中apsid对应的值-=piddr_meminfo表中的a的值的size成员的值
    
    if(!*size) bpf_map_delete_elem(&psid_count, &apsid);

    // del freeing addr info
    return bpf_map_delete_elem(&piddr_meminfo, &a);             //删除piddr_meminfo表中的a的值,因为已经释放了
}


SEC("uprobe/free")                                               //用户空间探针uprobe,挂载点为free函数
int BPF_KPROBE(free_enter, void *addr) {
    return gen_free_enter((u64)addr, 0);                        //当用户程序执行free函数，则执行gen_free_enter(addr, 0);
}


SEC("uprobe/realloc")                                           //用户空间探针uprobe,挂载点为realloc函数
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter((u64)ptr, 0);                                //当用户程序执行realloc函数，则执行gen_free_enter(ptr, 0),并返回gen_alloc_enter(size)
	return gen_alloc_enter(size);
}


SEC("uprobe/munmap")                                            //用户空间探针uprobe,挂载点为munmap函数
int BPF_KPROBE(munmap_enter, void *addr, size_t unsize) {
    return gen_free_enter((u64)addr, unsize);               //当用户程序执行munmap函数，则执行gen_free_enter(addr, unsize);

}
