#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int account_process_tick(struct pt_regs *ctx) {
    int user_tick = PT_REGS_PARM2(ctx);
    // bpf_trace_printk("Tick = %d\n", user_tick);
    return 0;
}

int account_user_time(struct pt_regs *ctx) {
    u64 cputime = (u64)PT_REGS_PARM2(ctx);
    // bpf_trace_printk("CPUTime = %d\n", cputime);
    return 0;
}

int account_system_time(struct pt_regs *ctx) {
    u64 cputime = (u64)PT_REGS_PARM3(ctx);
    bpf_trace_printk("CPUTime = %d\n", cputime);
    return 0;
}

int account_idle_ticks(struct pt_regs *ctx) {
    int ticks = PT_REGS_PARM1(ctx); // 本身就是int型的了，无需从内核读取
    // bpf_trace_printk("ticks = %d\n", ticks);
    return 0;
}