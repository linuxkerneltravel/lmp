# kvm_exit

考虑到频繁的虚拟机退出事件可能会导致性能问题，kvm_watcher中的kvm_exit子功能通过显示详细的退出原因和在一台主机上运行的所有vm的每个虚拟机的vcpu上的退出计数及处理时延，可以捕获和分析vm exit事件，该工具旨在定位频繁退出的原因（如EPT_VIOLATION、EPT_MISCONFIG、PML_FULL等）,在vm exit基础上，如果kvm这个时候因为某些原因，需要退出到用户态的hypervisor(比如qemu)，kvm就要设置KVM_EXIT_XXX，此工具包含了这两部分exit reason。

![kvm exit](https://gitee.com/nan-shuaibo/image/raw/master/202404251707665.png)

## 原理介绍

### VMX 操作模式

作为传统的 IA32 架构的扩展，VMX 操作模式在默认下是关闭的，只有当 VMM 需要使用硬件辅助虚拟化功能时才会使用 Intel 提供的两条新指令来开关 VMX 操作模式：

- `VMXON`：开启 VMX 操作模式。
- `VMXOFF`：关闭 VMX 操作模式。

在 Intel SDM 中描述的 VMX 生命周期如下：

- 软件通过 `VMXON` 指令进入 VMX 操作模式。
- VMM 可以通过 `VM entries` 进入 Guest VM（单次只能执行一个 VM），VMM 通过 `VMLAUNCH` （第一次进入 VM）与 `VMRESUME` （从 VMM 中恢复到 VM）指令来使能 `VM entry`，通过 `VM exits` 重获控制权。
- `VM exits` 通过 VMM 指定的入口点移交控制权，VMM 对 VM 的退出原因进行响应后通过 `VM entry` 返回到 VM 中。
- 当 VMM 想要停止自身运行并退出 VMX 操作模式时，其通过 `VMXOFF` 指令来完成。

![img](https://ctf-wiki.org/pwn/virtualization/basic-knowledge/figure/interaction-of-vmm-and-guest.png)

### VM exit和VM entry

**VM exit**：VM-Exit是指CPU从非根模式切换到根模式，从客户机切换到VMM的操作。引发VM-Exit的原因很多，例如在非根模式执行了敏感指令、发生了中断等。处理VM-Exit时间是VMM模拟指令、虚拟特权资源的一大任务。

**VM entry**：VM-Entry是指CPU由根模式切换到非根模式，从软件角度看，是指CPU从VMM切换到客户机执行。这个操作通常由VMM主动发起。在发起之前，VMM会设置好VMCS相关域的内容，例如客户机状态域、宿主机状态域等，然后执行VM-Entry指令。

以下是VM exit到VM entry的流程：

![VM entry 与 VM exit](https://ctf-wiki.org/pwn/virtualization/basic-knowledge/figure/vm-entry-and-exit.png)

### kvm_exit与kvm_userspace_exit

[vm exit和userspace exit](https://blog.csdn.net/weixin_46324627/article/details/136325212?spm=1001.2014.3001.5501)

## 挂载点

| 类型       | 名称                    |
| ---------- | ----------------------- |
| tracepoint | kvm_exit                |
| tracepoint | kvm_entry               |
| fentry     | kvm_arch_vcpu_ioctl_run |
| tracepoint | kvm_userspace_exit      |

## 示例输出

4391为主机上的虚拟机进程，4508、4509、4510...分别是虚拟机中的vcpu子进程，每隔两秒输出虚拟机中产生的exit事件及其处理延时等信息。
结果会以进程号（VM的唯一标识）以及线程号（VM中每个VCPU的唯一标识）的优先级依次从小到大的顺序输出。
```
ubuntu@rd350x:~/nans/lmp/eBPF_Supermarket/kvm_watcher$ sudo ./kvm_watcher -e

TIME:16:33:47
pid          tid          total_time   max_time     min_time     counts       reason      
------------ ------------ ------------ ------------ ------------ ------------ ------------
4391         4508         0.0067       0.0067       0.0067       1            MSR_READ    
             4509         0.0074       0.0038       0.0036       2            MSR_READ    
                          0.1354       0.0173       0.0006       48           MSR_WRITE   
                          0.6816       0.0639       0.0036       44           IO_INSTRUCTION
                          0.0030       0.0030       0.0030       1            EOI_INDUCED 
             4510         0.0043       0.0043       0.0043       1            MSR_READ    
                          0.0076       0.0049       0.0011       3            MSR_WRITE   
             4511         0.0053       0.0053       0.0053       1            MSR_READ    
                          0.0053       0.0053       0.0053       1            MSR_READ    
                          0.0288       0.0054       0.0012       9            MSR_WRITE   
             4512         0.0101       0.0061       0.0040       2            MSR_READ    
                          0.0317       0.0053       0.0011       11           MSR_WRITE   
             4513         0.0070       0.0036       0.0034       2            MSR_READ    
                          0.0493       0.0062       0.0010       17           MSR_WRITE   
             4514         0.0074       0.0074       0.0074       1            MSR_READ    
                          0.0254       0.0045       0.0008       10           MSR_WRITE   
             4515         0.0620       0.0051       0.0011       25           MSR_WRITE   
                          0.0079       0.0042       0.0038       2            MSR_READ    

TIME:16:33:49
pid          tid          total_time   max_time     min_time     counts       reason      
------------ ------------ ------------ ------------ ------------ ------------ ------------
4391         4508         0.0041       0.0041       0.0041       1            MSR_READ    
                          0.0199       0.0051       0.0012       8            MSR_WRITE   
             4509         0.0069       0.0039       0.0030       2            MSR_READ    
                          0.0063       0.0063       0.0063       1            PAUSE_INSTRUCTION
                          0.1592       0.0063       0.0006       68           MSR_WRITE   
                          0.4385       0.0545       0.0362       10           IO_INSTRUCTION
             4510         0.0035       0.0035       0.0035       1            MSR_READ    
                          0.0475       0.0063       0.0011       18           MSR_WRITE   
             4511         0.0073       0.0037       0.0036       2            MSR_READ    
                          0.0073       0.0037       0.0036       2            MSR_READ    
                          0.0179       0.0179       0.0179       1            EPT_VIOLATION
                          0.0437       0.0061       0.0011       17           MSR_WRITE   
             4512         0.0032       0.0032       0.0032       1            MSR_READ    
                          0.0699       0.0065       0.0011       30           MSR_WRITE   
             4513         0.0085       0.0044       0.0041       2            MSR_READ    
                          0.0476       0.0068       0.0012       16           MSR_WRITE   
             4514         0.0078       0.0045       0.0033       2            MSR_READ    
                          0.0320       0.0049       0.0011       12           MSR_WRITE   
             4515         0.0741       0.0051       0.0005       33           MSR_WRITE   
                          0.0083       0.0042       0.0041       2            MSR_READ    
```

## 参数解释

- **VM Exit 原因统计**：记录并展示触发 VM Exit 的具体原因，帮助用户理解 VM Exit 发生的上下文和背景。
- **VM Exit 延时分析**：统计每次 VM Exit 处理的最大、最小和总共延时，为性能分析提供量化数据。
- **VM Exit 次数计数**：计算每种类型的 VM Exit 发生的次数，帮助识别最频繁的性能瓶颈。
- **PID、TID号**：其中PID为主机侧的虚拟机进程号，TID为虚拟机内部的vcpu**的进程号**