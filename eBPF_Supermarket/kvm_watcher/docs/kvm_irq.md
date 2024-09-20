# kvm irq

## 概述

kvm watcher中的kvm irq子功能模块可以对kvm中的虚拟化中断事件的实时监控和分析能力，可以捕获和记录各种中断事件，支持监控传统的PIC中断、高级的IOAPIC中断以及基于消息的MSI中断，覆盖了KVM虚拟化环境中的主要中断类型。对于每个捕获的中断事件，记录详细信息，包括中断类型、中断注入延时、引脚号、触发方式、目标LAPIC的ID、向量号以及是否被屏蔽等关键数据。

![kvm_irq](https://gitee.com/nan-shuaibo/image/raw/master/202404251710847.png)

## 原理介绍

x86平台主要使用的中断类型有pic、apic及msi中断，在多核系统下的apic结构图如下所示，每个cpu有一个lapic，外部中断通过ioapic转发到lapic，如果是msi中断，则绕过了io apic直接发给lapic。

![img](https://img-blog.csdnimg.cn/20200411174750913.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3pneTY2Ng==,size_16,color_FFFFFF,t_70)

KVM_CREATE_IRQCHIP的ioctl用于在虚拟机初始化阶段创建中断请求芯片，当KVM接收到虚拟机相关联的ioctl系统调用时，函数kvm_vm_ioctl()进行处理调用kvm_arch_vm_ioctl()函数,该函数中完成了初始化pic和ioapic控制器模块，配置中断请求默认路由等任务，其中的kvm_setup_default_irq_routing会依次调用kvm_set_irq_routing和setup_routing_entry，最终调用kvm_set_routing_entry函数完成路由配置，核心操作是将各个类型中断控制器的中断置为函数与该类型的控制器路由入口进行绑定，以备后续发生中断请求时调用。

```
int kvm_set_routing_entry(struct kvm *kvm,
              struct kvm_kernel_irq_routing_entry *e,
              const struct kvm_irq_routing_entry *ue)
{
    switch (ue->type) {
    case KVM_IRQ_ROUTING_IRQCHIP: //中断路由芯片
        if (irqchip_split(kvm))
            return -EINVAL;
        e->irqchip.pin = ue->u.irqchip.pin;//设置中断芯片引脚
        switch (ue->u.irqchip.irqchip) {
        case KVM_IRQCHIP_PIC_SLAVE:
            e->irqchip.pin += PIC_NUM_PINS / 2; //从片引脚
            fallthrough;
        case KVM_IRQCHIP_PIC_MASTER:
            if (ue->u.irqchip.pin >= PIC_NUM_PINS / 2)
                return -EINVAL;
            //// 设置处理 PIC 中断的回调函数
            e->set = kvm_set_pic_irq; 
            break;
        case KVM_IRQCHIP_IOAPIC:
            if (ue->u.irqchip.pin >= KVM_IOAPIC_NUM_PINS)
                return -EINVAL;
            // 设置处理 IOPIC 中断的回调函数
            e->set = kvm_set_ioapic_irq;
            break;
        default:
            return -EINVAL;
        }
        e->irqchip.irqchip = ue->u.irqchip.irqchip;
        break;
    case KVM_IRQ_ROUTING_MSI:
        // 设置处理 MSI 中断的回调函数
        e->set = kvm_set_msi;
        e->msi.address_lo = ue->u.msi.address_lo;
        e->msi.address_hi = ue->u.msi.address_hi;
        e->msi.data = ue->u.msi.data;

        if (kvm_msi_route_invalid(kvm, e))
            return -EINVAL;
        break;
.....

    return 0;
}
```

KVM_CREATE_IRQCHIP用于虚拟机向VMM的虚拟apic发送中断请求，再有VMM将中断交付虚拟cpu处理，当kvm_vm_ioctl函数被调用并处理KVM_IRQ_LINE请求时会调用kvm_vm_ioctl_irq_line,该函数调用kvm_set_irq完成中断注入，其核心任务就是根据中断控制器类型调用之前所绑定的中断回调函数，这些中断回调函数会将中断请求写入虚拟cpu的vmcs中。

```
/* kvm_set_irq - 设置或清除 KVM 虚拟机中的一个中断
 * @kvm: 指向当前 KVM 实例的指针
 * @irq_source_id: 中断源的标识符，用于区分不同的中断源
 * @irq: 要操作的中断号
 * @level: 指定中断的电平，通常 1 表示触发中断，0 表示清除中断
 * @line_status: 指定中断线路的当前状态
 *
 * Return value:
 *  < 0   中断被忽略（被屏蔽或其他原因未被送达）
 *  = 0   中断被合并（之前的中断仍在等待处理）
 *  > 0   中断成功送达的 CPU 数量
 */
 int kvm_set_irq(struct kvm *kvm, int irq_source_id, u32 irq, int level,
        bool line_status)
{
    struct kvm_kernel_irq_routing_entry irq_set[KVM_NR_IRQCHIPS];
    ....
     
    while (i--) {
        int r;
        r = irq_set[i].set(&irq_set[i], kvm, irq_source_id, level,
                   line_status);
        if (r < 0)
            continue;

        ret = r + ((ret < 0) ? 0 : ret);
    }

    return ret;
}
```

其中`irq_set[i].set`函数就是不同中断类型的回调函数。

当需要注入的中断为msi类型时，kvm_vm_ioctl会处理为KVM_SIGNAL_MSI类型的的请求，依次调用kvm_send_userspace_msi和kvm_set_msi

其中ioapic的回调函数kvm_set_ioapic_irq依次调用kvm_ioapic_set_irq、ioapic_set_irq最后调用ioapic_service函数，ioapic_service主要是找到中断的重映射表，然后查找中断的目的地信息并转发到对应vcpu的lapic去处理。然后会调用kvm_irq_delivery_to_apic负责将中断分发给lapic。

>  中断虚拟化详细介绍可以参考：[kvm中断虚拟化 ](https://blog.csdn.net/zgy666/article/details/105456569) 
>  [内核虚拟化：虚拟中断注入](https://blog.csdn.net/weixin_46324627/article/details/136661252?csdn_share_tail=%7B%22type%22%3A%22blog%22%2C%22rType%22%3A%22article%22%2C%22rId%22%3A%22136661252%22%2C%22source%22%3A%22weixin_46324627%22%7D)

## 挂载点

| 类型          | 名称            |
| ------------- | --------------- |
| fentry、fexit | kvm_pic_set_irq |
| fentry、fexit | ioapic_set_irq  |
| fentry、fexit | kvm_set_msi     |

## 示例输出

```
#sudo ./kvm_watcher -c
TIME(ms)           COMM            PID        DELAY      TYPE/PIN       DST/VEC    OTHERS  
962804587.768667   CPU 0/KVM       269394     773        MSI       /-   0x2/40     Fixed  |physical|edge |-     |-
962805792.231419   vhost-529746    529767     3008       MSI       /-   0x1/40     Fixed  |physical|edge |-     |-
962805792.234556   vhost-269394    269403     1442       MSI       /-   0x3/40     Fixed  |physical|edge |-     |-
962805792.243754   vhost-426070    426078     1323       MSI       /-   0x5/35     Fixed  |physical|edge |-     |-
962806603.650275   CPU 0/KVM       269394     3738       MSI       /-   0x2/40     Fixed  |physical|edge |-     |-
962806603.713743   CPU 0/KVM       269394     1414       MSI       /-   0x2/40     Fixed  |physical|edge |-     |-
962806816.308239   qemu-system-x86 269394     29495      IOAPIC    /21  0x4/39     Fixed  |physical|level|-     |-
962806816.359852   qemu-system-x86 269394     38615      PIC slave /2   -  /-      -      |-       |level|masked|-
962806816.400501   qemu-system-x86 269394     1259       IOAPIC    /10  0  /0      Fixed  |physical|edge |masked|-
962806816.408792   qemu-system-x86 269394     1270       PIC slave /2   -  /-      -      |-       |level|masked|-
962806816.410425   qemu-system-x86 269394     226        IOAPIC    /10  0  /0      Fixed  |physical|edge |masked|-
962809792.316035   vhost-426070    426078     1747       MSI       /-   0x5/35     Fixed  |physical|edge |-     |-
962810635.636493   CPU 0/KVM       269394     3034       MSI       /-   0x2/40     Fixed  |physical|edge |-     |-
962810635.694923   CPU 0/KVM       269394     897        MSI       /-   0x2/40     Fixed  |physical|edge |-     |-
962811776.481253   vhost-269394    269403     3719       MSI       /-   0x3/40     Fixed  |physical|edge |-     |-
962811776.523581   vhost-529746    529767     1664       MSI       /-   0x1/40     Fixed  |physical|edge |-     |-
962811776.654516   vhost-426070    426078     1522       MSI       /-   0x5/35     Fixed  |physical|edge |-     |-
962812652.302519   CPU 2/KVM       269394     2605       MSI       /-   0x2/40     Fixed  |physical|edge |-     |-
962812652.342239   CPU 2/KVM       269394     749        MSI       /-   0x2/40     Fixed  |physical|edge |-     |-
962813344.856419   qemu-system-x86 269394     23230      IOAPIC    /21  0x4/39     Fixed  |physical|level|-     |-
962813344.899277   qemu-system-x86 269394     5472       PIC slave /2   -  /-      -      |-       |level|masked|-
```

> 对于IOAPIC和PIC类型的中断,pin是引脚号，DST/VEC表示目标vcpu id和中断向量号
>
> others中的第一列是中断分发方式，第二列是中断目标的寻址模式，第三列表示中断信号的触发方式，第四列表示中断是否被屏蔽，第五列表示中断是否合并。