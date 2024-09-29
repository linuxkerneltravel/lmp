#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mem_watcher.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message) {
    // 打印 OOM 触发信息
    bpf_printk("oom_kill_process triggered\n");

    // 准备存储事件数据
    struct event *task_info;
    task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!task_info) {
        return 0;
    }

    // 获取被 OOM 杀死的进程
    struct task_struct *p;
    bpf_probe_read(&p, sizeof(p), &oc->chosen);
    bpf_probe_read(&task_info->oomkill_pid, sizeof(task_info->oomkill_pid), &p->pid);

    // 获取被杀进程的命令名 (comm)
    bpf_probe_read(&task_info->comm, sizeof(task_info->comm), &p->comm);

    // 获取触发 OOM 的进程信息
    struct task_struct *trigger_task = (struct task_struct *)bpf_get_current_task();
    task_info->triggered_pid = BPF_CORE_READ(trigger_task, pid);

    // 获取未被杀掉的进程的内存页信息
    struct mm_struct *mm;
    mm = BPF_CORE_READ(trigger_task, mm);
    if (mm) {
        task_info->mem_pages = BPF_CORE_READ(mm, total_vm);  // 获取进程的虚拟内存页面总数
    } else {
        task_info->mem_pages = 0;  // 如果进程没有分配内存
    }

    // 提交事件
    bpf_ringbuf_submit(task_info, 0);

    return 0;
}
