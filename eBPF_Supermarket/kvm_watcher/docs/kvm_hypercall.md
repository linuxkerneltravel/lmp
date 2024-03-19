# kvm hypercall

## 概述

kvm watcher 的 kvm hypercall 子模块是一个专为 KVM 虚拟化环境设计的监控工具，它能够详细记录虚拟机进行 hypercall 时的相关信息。Hypercall 允许 Guest OS 以高效的方式直接与 Hypervisor 通信，从而优化虚拟机的性能，特别是在内存管理、设备 I/O 等方面。

## 原理介绍

在虚拟化环境中，Hypercall 机制是虚拟机（VM）从非特权模式（no root mode）切换到特权模式（root mode）的一种方式，类似于传统操作系统中从用户态切换到内核态的系统调用（syscall）。KVM（Kernel-based Virtual Machine）通过支持 Hypercall 机制，提供了一种高效的方式让虚拟机的 Guest OS 执行一些需要更高权限的操作，比如更新页表或访问物理资源等，这些操作由于虚拟机的非特权域无法完成，因此通过 Hypercall 交由 Hypervisor 来执行。

<div align=center><img src="http://s2.51cto.com/wyfs02/M01/79/F3/wKiom1afF9-BZbZuAAAotW_0zjg092.png"></div>

hypercall的发起需求触发vm exit原因为EXIT_REASON_VMCALL，其对应的处理函数为：

```
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
...
  [EXIT_REASON_VMCALL]                  = kvm_emulate_hypercall,
...
};
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

## 挂载点

| 类型   | 名称                  |
| ------ | --------------------- |
| fentry | kvm_emulate_hypercall |

## 示例输出

```
#sudo ./kvm_watcher -h
TIME:19:49:29
PID          VCPU_ID      NAME         COUNTS       HYPERCALLS  
269394       3            KICK_CPU     1            3599        
------------------------------------------------------------------------
TIME:19:49:46
PID          VCPU_ID      NAME         COUNTS       HYPERCALLS  
426070       0            SEND_IPI     1            503         
------------------------------------------------------------------------
TIME:19:49:50
PID          VCPU_ID      NAME         COUNTS       HYPERCALLS  
269394       1            SEND_IPI     9            2962        
426070       0            SEND_IPI     7            510         
426070       6            KICK_CPU     1            259         
269394       2            KICK_CPU     13           4375        
426070       0            KICK_CPU     1            511         
269394       3            SEND_IPI     9            3611        
426070       2            KICK_CPU     1            135         
269394       0            KICK_CPU     3            2178        
269394       3            KICK_CPU     4            3612        
269394       4            KICK_CPU     10           2409        
426070       4            KICK_CPU     1            216         
269394       2            SEND_IPI     2            4366        
269394       1            KICK_CPU     4            2953        
269394       4            SEND_IPI     10           2410        
269394       0            SEND_IPI     1            2176        
426070       1            KICK_CPU     1            234         
426070       3            KICK_CPU     1            223         
269394       5            KICK_CPU     3            2564        
------------------------------------------------------------------------
TIME:19:49:52
PID          VCPU_ID      NAME         COUNTS       HYPERCALLS  
426070       3            SEND_IPI     1            225         
426070       4            SEND_IPI     6            222         
426070       7            SEND_IPI     13           214         
269394       3            KICK_CPU     2            3614        
269394       2            SEND_IPI     3            4378        
426070       1            KICK_CPU     1            235         
426070       3            KICK_CPU     1            224         
269394       5            KICK_CPU     1            2565        
------------------------------------------------------------------------
TIME:19:49:54
PID          VCPU_ID      NAME         COUNTS       HYPERCALLS  
426070       4            SCHED_YIELD  3            385         
269394       1            SEND_IPI     1            2963        
269394       5            SEND_IPI     3            2568        
426070       1            SEND_IPI     18           253         
426070       3            SEND_IPI     95           321         
426070       0            SEND_IPI     1            512         
426070       4            SEND_IPI     162          387         
426070       7            SEND_IPI     10           224         
269394       3            SEND_IPI     2            3616        
269394       4            SEND_IPI     2            2412        
269394       0            SEND_IPI     1            2179        
426070       3            KICK_CPU     1            262   
```

其中详细的参数信息会输出到临时文件：

```
TIME(ms)           COMM            PID        VCPU_ID    NAME       HYPERCALLS ARGS      
881915483.793962   CPU 0/KVM       529746     0          SEND_IPI   7          ipi_bitmap_low:0x1,ipi_bitmap_high:0,min(apic_id):1,icr:0xf8
881915485.648450   CPU 2/KVM       269394     2          KICK_CPU   4360       apic_id:3
881919197.181233   CPU 3/KVM       269394     3          KICK_CPU   3598       apic_id:4
881929597.162056   CPU 3/KVM       269394     3          KICK_CPU   3599       apic_id:2
881946045.818584   CPU 0/KVM       426070     0          SEND_IPI   503        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xf8
881948845.323275   CPU 3/KVM       269394     3          KICK_CPU   3600       apic_id:0
881949425.157070   CPU 6/KVM       426070     6          KICK_CPU   259        apic_id:1
881949425.573460   CPU 1/KVM       426070     1          KICK_CPU   234        apic_id:3
881949426.064405   CPU 3/KVM       426070     3          KICK_CPU   223        apic_id:2
881949426.514380   CPU 2/KVM       426070     2          KICK_CPU   135        apic_id:4
881949426.910918   CPU 4/KVM       426070     4          KICK_CPU   216        apic_id:5
881949459.202569   CPU 0/KVM       426070     0          SEND_IPI   504        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xfc
881949459.384313   CPU 0/KVM       426070     0          SEND_IPI   505        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xfc
881949459.607809   CPU 0/KVM       426070     0          SEND_IPI   506        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xfc
881949459.761529   CPU 0/KVM       426070     0          SEND_IPI   507        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xfc
881949485.192198   CPU 0/KVM       426070     0          SEND_IPI   508        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xfc
881949485.517598   CPU 0/KVM       426070     0          SEND_IPI   509        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xfc
881949485.849330   CPU 0/KVM       426070     0          SEND_IPI   510        ipi_bitmap_low:0x7f,ipi_bitmap_high:0,min(apic_id):1,icr:0xfc
```

## 参数解释

- **PID**: 相应虚拟机进程的标识符（PID）
- **VCPU_ID**:对应的vcpu标识符
- **NAME**:所发生的hypercall名称
- **COUNTS**:当前时间段内hypercall发送的次数
- **HYPERCALLS**:自虚拟机启动以来，每个vcpu上发生的hypercall的次数