from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

b = BPF(text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

struct mini_regs {
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

struct user_vmas {
    unsigned long start_code;
    unsigned long end_code;
    unsigned long start_data;
    unsigned long end_data;
    unsigned long start_brk;
    unsigned long brk;
    unsigned long start_stack;
};

struct stack_regs_info {
    struct mini_regs    user_regs;
    struct mini_regs    user_save_regs;
    struct mini_regs    kern_regs;
    struct user_vmas    user_vmas;
    int                 finished;
};

BPF_HASH(user_to_kern, u32, struct stack_regs_info);

static void restore_regs(struct mini_regs *mr, struct pt_regs *regs)
{
    bpf_probe_read_kernel(&(mr->ip), sizeof(unsigned long), &(regs->ip));
    bpf_probe_read_kernel(&(mr->cs), sizeof(unsigned long), &(regs->cs));
    bpf_probe_read_kernel(&(mr->flags), sizeof(unsigned long), &(regs->flags));
    bpf_probe_read_kernel(&(mr->sp), sizeof(unsigned long), &(regs->sp));
    bpf_probe_read_kernel(&(mr->ss), sizeof(unsigned long), &(regs->ss));
}

static void restore_vmas(struct user_vmas *uv, struct mm_struct *mm)
{
    bpf_probe_read_kernel(&(uv->start_code), sizeof(unsigned long), &(mm->start_code));
    bpf_probe_read_kernel(&(uv->end_code), sizeof(unsigned long), &(mm->end_code));
    bpf_probe_read_kernel(&(uv->start_data), sizeof(unsigned long), &(mm->start_data));
    bpf_probe_read_kernel(&(uv->end_data), sizeof(unsigned long), &(mm->end_data));
    bpf_probe_read_kernel(&(uv->start_brk), sizeof(unsigned long), &(mm->start_brk));
    bpf_probe_read_kernel(&(uv->brk), sizeof(unsigned long), &(mm->brk));
    bpf_probe_read_kernel(&(uv->start_stack), sizeof(unsigned long), &(mm->start_stack));
}

int get_user_regs(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct stack_regs_info *psri, sri = {};

    psri = user_to_kern.lookup(&pid);
    if (!psri) {
        restore_regs(&(sri.user_regs), ctx);
        sri.finished = 0;

        user_to_kern.update(&pid, &sri);
    }

    return 0;
}

int get_kern_regs(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    struct stack_regs_info *psri;

    psri = user_to_kern.lookup(&pid);
    if (psri && !psri->finished) {
        restore_regs(&(psri->user_save_regs), regs);
        restore_regs(&(psri->kern_regs), ctx);
        restore_vmas(&(psri->user_vmas), curr->mm);
        psri->finished = 1;

    }

    return 0;
}

""")

b.attach_uprobe(name="c", sym="read", fn_name="get_user_regs")
b.attach_kprobe(event="__x64_sys_read", fn_name="get_kern_regs")

while 1:
    sleep(1)

    user_to_kern = b.get_table("user_to_kern")

    for k, v in user_to_kern.items():
        uregs = v.user_regs
        sregs = v.user_save_regs
        kregs = v.kern_regs
        uvmas = v.user_vmas

        print("###\npid: ", k.value)
        print("ip cs flags sp ss")
        print("user_runn: ", uregs.ip, uregs.cs, uregs.flags, uregs.sp, uregs.ss)
        print("user_save: ", sregs.ip, sregs.cs, sregs.flags, sregs.sp, sregs.ss)
        print("kern_runn: ", kregs.ip, kregs.cs, kregs.flags, kregs.sp, kregs.ss)
        print("start_code end_code start_data end_data start_brk brk start_stack")
        print("user_vmas: ", uvmas.start_code, uvmas.end_code, uvmas.start_data, uvmas.end_data, uvmas.start_brk, uvmas.brk, uvmas.start_stack)
    user_to_kern.clear()  
