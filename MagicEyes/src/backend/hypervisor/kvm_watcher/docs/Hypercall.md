> 在Linux中，大家应该对syscall非常的了解和熟悉，其是用户态进入内核态的一种途径或者说是一种方式，完成了两个模式之间的切换；而在虚拟环境中，有没有一种类似于syscall这种方式，能够从no root模式切换到root模式呢？答案是肯定的，KVM提供了Hypercall机制，x86体系架构也有相关的指令支持。
>
> hypercall：当虚拟机的Guest OS需要执行一些更高权限的操作（如：页表的更新、对物理资源的访问等）时，由于自身在非特权域无法完成这些操作，于是便通过调用Hypercall交给Hypervisor来完成这些操作。

## Hypercall的发起

KVM代码中提供了五种形式的Hypercall接口：

```
file: arch/x86/include/asm/kvm_para.h, line: 34
static inline long kvm_hypercall0(unsigned int nr);
static inline long kvm_hypercall1(unsigned int nr, unsigned long p1);
static inline long kvm_hypercall2(unsigned int nr, unsigned long p1, unsigned long p2);
static inline long kvm_hypercall3(unsigned int nr, unsigned long p1, unsigned long p2, unsigned long p3)
static inline long kvm_hypercall4(unsigned int nr, unsigned long p1, unsigned long p2, unsigned long p3, unsigned long p4)
```

这几个接口的区别在于参数个数的不用，本质是一样的。挑个参数最多的看下：

```
static inline long kvm_hypercall4(unsigned int nr, unsigned long p1,
                  unsigned long p2, unsigned long p3,
                  unsigned long p4)
{
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2), "d"(p3), "S"(p4)
             : "memory");
    return ret;
}
```

Hypercall内部实现是标准的内嵌汇编,稍作分析：

### KVM_HYPERCALL

```
#define KVM_HYPERCALL ".byte 0x0f,0x01,0xc1"
```

对于KVM hypercall来说，KVM_HYPERCALL是一个三字节的指令序列，x86体系架构下即是vmcall指令，官方手册解释：

```
vmcall：
    op code:0F 01 C1 -- VMCALL Call to VM
 monitor 
by causing VM exit
```

言简意赅，vmcall会导致VM exit到VMM。

### 返回值

: “=a”(ret)，表示返回值放在eax寄存器中输出。

### 输入

: “a”(nr), “b”(p1), “c”(p2), “d”(p3), “S”(p4),表示输入参数放在对应的eax，ebx，ecx，edx，esi中，而nr其实就是可以认为是系统调用号。

## hypercall的处理

当Guest发起一次hypercall后，VMM会接管到该call导致的VM Exit。

```
static int (*const kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
    ......
    [EXIT_REASON_VMCALL]                  = kvm_emulate_hypercall,
    ......
}
```

进入kvm_emulate_hypercall()处理，过程非常简单：

```
int kvm_emulate_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;
	int op_64_bit;

	// 检查是否启用了Xen超级调用，如果是，则调用Xen超级调用处理函数
	if (kvm_xen_hypercall_enabled(vcpu->kvm))
		return kvm_xen_hypercall(vcpu);

	// 检查是否启用了Hypervisor超级调用，如果是，则调用Hypervisor超级调用处理函数
	if (kvm_hv_hypercall_enabled(vcpu))
		return kvm_hv_hypercall(vcpu);

	// 从寄存器中读取超级调用号及参数
	nr = kvm_rax_read(vcpu);
	a0 = kvm_rbx_read(vcpu);
	a1 = kvm_rcx_read(vcpu);
	a2 = kvm_rdx_read(vcpu);
	a3 = kvm_rsi_read(vcpu);

	// 记录超级调用的追踪信息
	trace_kvm_hypercall(nr, a0, a1, a2, a3);

	// 检查是否为64位超级调用
	op_64_bit = is_64_bit_hypercall(vcpu);
	if (!op_64_bit) {
		nr &= 0xFFFFFFFF;
		a0 &= 0xFFFFFFFF;
		a1 &= 0xFFFFFFFF;
		a2 &= 0xFFFFFFFF;
		a3 &= 0xFFFFFFFF;
	}

	// 检查当前CPU的特权级是否为0
	if (static_call(kvm_x86_get_cpl)(vcpu) != 0) {
		ret = -KVM_EPERM;
		goto out;
	}

	ret = -KVM_ENOSYS;

	// 根据超级调用号执行相应的操作
	switch (nr) {
	case KVM_HC_VAPIC_POLL_IRQ:
		ret = 0;
		break;
	case KVM_HC_KICK_CPU:
		// 处理CPU唤醒的超级调用
		if (!guest_pv_has(vcpu, KVM_FEATURE_PV_UNHALT))
			break;

		kvm_pv_kick_cpu_op(vcpu->kvm, a1);
		kvm_sched_yield(vcpu, a1);
		ret = 0;
		break;
#ifdef CONFIG_X86_64
	case KVM_HC_CLOCK_PAIRING:
		// 处理时钟配对的超级调用
		ret = kvm_pv_clock_pairing(vcpu, a0, a1);
		break;
#endif
	case KVM_HC_SEND_IPI:
		// 处理发送中断请求的超级调用
		if (!guest_pv_has(vcpu, KVM_FEATURE_PV_SEND_IPI))
			break;

		ret = kvm_pv_send_ipi(vcpu->kvm, a0, a1, a2, a3, op_64_bit);
		break;
	case KVM_HC_SCHED_YIELD:
		// 处理调度让出的超级调用
		if (!guest_pv_has(vcpu, KVM_FEATURE_PV_SCHED_YIELD))
			break;

		kvm_sched_yield(vcpu, a0);
		ret = 0;
		break;
	case KVM_HC_MAP_GPA_RANGE:
		// 处理GPA范围映射的超级调用
		ret = -KVM_ENOSYS;
		if (!(vcpu->kvm->arch.hypercall_exit_enabled & (1 << KVM_HC_MAP_GPA_RANGE)))
			break;

		// 设置KVM_EXIT_HYPERCALL退出类型，并填充相关信息
		vcpu->run->exit_reason        = KVM_EXIT_HYPERCALL;
		vcpu->run->hypercall.nr       = KVM_HC_MAP_GPA_RANGE;
		vcpu->run->hypercall.args[0]  = a0;
		vcpu->run->hypercall.args[1]  = a1;
		vcpu->run->hypercall.args[2]  = a2;
		vcpu->run->hypercall.longmode = op_64_bit;
		vcpu->arch.complete_userspace_io = complete_hypercall_exit;
		return 0;
	default:
		ret = -KVM_ENOSYS;
		break;
	}

out:
	// 如果不是64位超级调用，则返回值需要截断为32位
	if (!op_64_bit)
		ret = (u32)ret;
	kvm_rax_write(vcpu, ret);

	// 更新超级调用统计信息，并跳过被模拟的指令
	++vcpu->stat.hypercalls;
	return kvm_skip_emulated_instruction(vcpu);
}
```

### Conclusion

整个过程非常简洁和简单，hypercall机制给了Guest能够主动进入VMM的一种方式。

## 调用号

```
#define KVM_HC_VAPIC_POLL_IRQ		1
#define KVM_HC_MMU_OP			2
#define KVM_HC_FEATURES			3
#define KVM_HC_PPC_MAP_MAGIC_PAGE	4
#define KVM_HC_KICK_CPU			5
#define KVM_HC_MIPS_GET_CLOCK_FREQ	6
#define KVM_HC_MIPS_EXIT_VM		7
#define KVM_HC_MIPS_CONSOLE_OUTPUT	8
#define KVM_HC_CLOCK_PAIRING		9
#define KVM_HC_SEND_IPI		10
#define KVM_HC_SCHED_YIELD		11
#define KVM_HC_MAP_GPA_RANGE		12
```


1. ##### KVM_HC_VAPIC_POLL_IRQ

------------------------

Architecture: x86
Status: active
Purpose: 触发客户机退出，以便在重新进入时主机可以检查待处理的中断。

2. ##### KVM_HC_MMU_OP

----------------

Architecture: x86
Status: deprecated.
Purpose: 支持内存管理单元（MMU）操作，例如写入页表项（PTE）、刷新转换后备缓冲（TLB）以及释放页表（PT）。

3. ##### KVM_HC_FEATURES

------------------

Architecture: PPC
Status: active
Purpose: 向客户机公开超级调用的可用性。在 x86 平台上，使用 cpuid 来列举可用的超级调用。在 PPC（PowerPC）上，可以使用基于设备树的查找（也是 EPAPR 规定的方式）或 KVM 特定的列举机制（即这个超级调用）。

4. ##### KVM_HC_PPC_MAP_MAGIC_PAGE

----------------------------

Architecture: PPC
Status: active
Purpose:为了实现超级监视器与客户机之间的通信，存在一个共享页面，其中包含了监视器可见寄存器状态的部分。客户机可以通过使用此超级调用将这个共享页面映射，以通过内存访问其监视器寄存器。

5. ##### KVM_HC_KICK_CPU

------------------

Architecture: x86
Status: active
Purpose: 用于唤醒处于 HLT（Halt）状态的vCPU 。
Usage example:
一个使用了半虚拟化的客户机的虚拟 CPU，在内核模式下忙等待某个事件的发生（例如，自旋锁变为可用）时，如果其忙等待时间超过了一个阈值时间间隔，就可以执行 HLT 指令。执行 HLT 指令将导致 hypervisor 将虚拟 CPU 置于休眠状态，直到发生适当的事件。同一客户机的另一个虚拟 CPU 可以通过发出 KVM_HC_KICK_CPU 超级调用来唤醒正在睡眠的虚拟 CPU，指定要唤醒的虚拟 CPU 的 APIC ID（a1）。另外一个参数（a0）在这个超级调用中用于将来的用途。


6. ##### KVM_HC_CLOCK_PAIRING

-----------------------

Architecture: x86
Status: active
Purpose: 用于同步主机和客户机时钟。

Usage:
a0：客户机物理地址，用于存储主机复制的 "struct kvm_clock_offset" 结构。

a1：时钟类型，目前只支持 KVM_CLOCK_PAIRING_WALLCLOCK（0）（对应主机的 CLOCK_REALTIME 时钟）。

```c
struct kvm_clock_pairing {
    __s64 sec;          // 从 clock_type 时钟起的秒数。
    __s64 nsec;         // 从 clock_type 时钟起的纳秒数。
    __u64 tsc;          // 用于计算 sec/nsec 对的客户机 TSC（时间戳计数）值。
    __u32 flags;        // 标志，目前未使用（为 0）。
    __u32 pad[9];       // 填充字段，目前未使用。
};
```

这个超级调用允许客户机在主机和客户机之间计算精确的时间戳。客户机可以使用返回的 TSC（时间戳计数）值来计算其时钟的 CLOCK_REALTIME，即在同一时刻。

如果主机不使用 TSC 时钟源，或者时钟类型不同于 KVM_CLOCK_PAIRING_WALLCLOCK，则返回 KVM_EOPNOTSUPP。

7. ##### KVM_HC_SEND_IPI

------------------

Architecture: x86
Status: active
Purpose: 向多个vcpu发生ipi。

- `a0`: 目标 APIC ID 位图的低位部分。
- `a1`: 目标 APIC ID 位图的高位部分。
- `a2`: 位图中最低的                         。
- `a3`: 中断命令寄存器。

这个超级调用允许客户机发送组播中断处理请求（IPIs），每次调用最多可以有 128 个目标（在 64 位模式下）或者 64 个虚拟中央处理单元（vCPU）（在 32 位模式下）。目标由位图表示，位图包含在前两个参数中（a0 和 a1）。a0 的第 0 位对应于第三个参数 a2 中的 APIC ID，a0 的第 1 位对应于 a2+1 的 APIC ID，以此类推。

返回成功传递 IPIs 的 CPU 数量。

8. ##### KVM_HC_SCHED_YIELD

---------------------

Architecture: x86
Status: active
Purpose: 用于在目标vCPU被抢占时进行让步。

a0: destination APIC ID

Usage example: 当向多个vCPU发送调用函数中断（call-function IPI）时，如果任何目标 vCPU 被抢占，进行让步。

9. ##### KVM_HC_MAP_GPA_RANGE

-------------------------

Architecture: x86
Status: active
Purpose: 请求 KVM 映射一个具有指定属性的 GPA 范围。

`a0`: 起始页面的客户机物理地址
`a1`: （4KB）页面的数量（在 GPA 空间中必须是连续的）
`a2`: 属性

    属性：
    位 3:0 - 首选页大小编码，0 = 4KB，1 = 2MB，2 = 1GB，以此类推...
    位 4 - 明文 = 0，加密 = 1
    位 63:5 - 保留（必须为零）

**实现注意事项**

此超级调用通过 KVM_CAP_EXIT_HYPERCALL 能力在用户空间中实现。在向客户机 CPUID 中添加 KVM_FEATURE_HC_MAP_GPA_RANGE 之前，用户空间必须启用该能力。此外，如果客户机支持 KVM_FEATURE_MIGRATION_CONTROL，用户空间还必须设置一个 MSR 过滤器来处理对 MSR_KVM_MIGRATION_CONTROL 的写入。

可以通过如下查看发生的hypercall信息：

```
root@nans:/sys/kernel/debug/tracing/events/kvm# echo 0 > ../../tracing_on
root@nans:/sys/kernel/debug/tracing/events/kvm# echo 1 > kvm_hypercall/enable 
root@nans:/sys/kernel/debug/tracing/events/kvm# echo 1 > ../../tracing_on
root@nans:/sys/kernel/debug/tracing/events/kvm# cat ../../trace_pipe 
```

输出如下：

![image-20240110125350965](https://gitee.com/nan-shuaibo/image/raw/master/202401101258714.png)

使用ebpf技术统计hypercall信息：

统计两秒内的每个hypercall发生的次数，和自客户机启动以来每个vcpu上发生的hypercall的次数

```
------------------------------------------------------------------------
TIME:16:22:05
PID          VCPU_ID      NAME         COUNTS       HYPERCALLS  
68453        4            KICK_CPU     1            0           
68453        2            KICK_CPU     1            0           
68453        1            SEND_IPI     6            5           
68453        0            SEND_IPI     7            7           
68453        7            KICK_CPU     1            0           
68453        0            KICK_CPU     1            0           
------------------------------------------------------------------------
TIME:16:22:07
PID          VCPU_ID      NAME         COUNTS       HYPERCALLS  
68082        4            KICK_CPU     2            45          
68453        5            SEND_IPI     3            2           
68453        6            SCHED_YIELD  2            66          
68453        6            SEND_IPI     79           80          
68453        3            SEND_IPI     45           44          
68453        1            SEND_IPI     23           28          
68453        0            SEND_IPI     7            14          
68453        4            SEND_IPI     145          145   
```

并将详细信息输出至临时文件

![image-20240301162527679](https://gitee.com/nan-shuaibo/image/raw/master/202403011629545.png)

