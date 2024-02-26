#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#include "sa_ebpf.h"
#include "task.h"

DeclareCommonMaps(stack_tuple);
DeclareCommonVar();

//传进来的参数
int apid = 0; 
// int acpu = 0;

const char LICENSE[] SEC("license") = "GPL";

static int handle(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct* curr = (struct task_struct*)bpf_get_current_task(); //利用bpf_get_current_task()获得当前的进程tsk
    ignoreKthread(curr);
    // u32 cpu_id = bpf_get_smp_processor_id();
    // if(cpu_id != acpu){
    //     return 0;
    // }
    stack_tuple key = {}; 
    u32 pid = get_task_ns_pid(curr);                                        //利用帮助函数获得当前进程的pid
    if ((apid >= 0 && pid != apid) || !pid || pid == self_pid)
        return 0;
 
    u32 tgid = get_task_ns_tgid(curr);                                      //利用帮助函数获取进程的tgid
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);                   //将pid_tgid表中的pid选项更新为tgid,若没有该表项，则创建
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);                         //p指向pid_comm哈希表中的pid表项对应的value
    if (!p)                                                                 //如果p不为空，获取当前进程名保存至name中，如果pid_comm当中不存在pid name项，则更新
    {
        comm name;
        bpf_get_current_comm(&name, COMM_LEN);
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);
        p = &name;
    }
    key.name = *p;
    u32 *t = bpf_map_lookup_elem(&pid_tgid, &pid);
    if(!t){
        key.tgid = 0xffffffff;
    }else{
        key.tgid = *t;
    }

    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,                                        
        .ksid = k ? KERNEL_STACK : -1,                                      
    };
     stack_tuple *d = bpf_map_lookup_elem(&psid_count, &apsid);                 //d指向psid_count表当中的apsid表项的值
                         
    if(!d) {
        stack_tuple nd = {.count = 1, .name = key.name,.tgid = key.tgid};
        bpf_map_update_elem(&psid_count, &apsid, &nd, BPF_NOEXIST);
    } else {
       d->count++;
    }
    return 0;

}

#define io_sec_tp(name)                         \
    SEC("tp/syscalls/sys_enter_" #name) \
    int prog_t_##name(struct trace_event_raw_sys_enter *ctx) { return handle(ctx); }

io_sec_tp(write);
io_sec_tp(read);
