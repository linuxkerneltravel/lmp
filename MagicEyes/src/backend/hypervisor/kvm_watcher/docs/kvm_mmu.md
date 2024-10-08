# kvm_mmu

## 概述

kvm watcher中的kvm mmu子功能模块特别关注于捕捉和分析两类关键的虚拟化环境中的内存管理事件：MMIO page fault和 EPT page fault。MMIO page fault发生在虚拟机尝试访问已映射为 I/O 设备的内存地址时。EPT page fault指的是当虚拟机访问的虚拟地址未在 EPT 中有效映射时发生的错误。

## 原理介绍

### EPT page fault

EPT 并不干扰 Guest VM 操作自身页表的过程，其本质上是**额外提供了一个 Guest 物理地址空间到 Host 物理地址空间转换的页表**，即使用一个额外的页表来完成 `GPA→HPA` 的转换。

EPT 方案虽然相比起影子页表而言多了一层转换，但是并不需要干扰 Guest 原有的页表管理，**GVA→GPA→HPA 的过程都由硬件自动完成**，同时 Hypervisor 仅需要截获 `EPT Violation` 异常（EPT 表项为空），效率提高了不少。

当虚拟化环境中产生page fault时，其中GVA->GPA的转换不触发vm exit，由虚拟机内部页表完成填充，GPA->HPA的转换会触发vm exit原因为EPT_VIOLATION,由kvm完成对TDP（Two-Dimensional Paging）页表的填充。

内核中的vm exit（EPT_VIOLATION）处理流程如下：

```
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
...
  [EXIT_REASON_EPT_VIOLATION]       = handle_ept_violation,
...
};

vmx_handle_exit() {
  # 处理 VMX（虚拟机扩展）退出的主要函数
  __vmx_handle_exit() {
    handle_ept_violation() {
      # 处理 EPT（扩展页表）违规的函数
      kvm_mmu_page_fault() {
        # 处理 KVM MMU（内存管理单元）页错误
        kvm_tdp_page_fault() {
          # 处理 TDP（两级页表）页错误
          kvm_arch_has_noncoherent_dma();
          direct_page_fault() {
            # 处理直接页错误
            kvm_vcpu_gfn_to_memslot();
            page_fault_handle_page_track();
            fast_page_fault();
            mmu_topup_memory_caches() {
              # 增加内存缓存
              kvm_mmu_topup_memory_cache() {
                __kvm_mmu_topup_memory_cache();
              }
              kvm_mmu_topup_memory_cache() {
                __kvm_mmu_topup_memory_cache();
              }
              kvm_mmu_topup_memory_cache() {
                __kvm_mmu_topup_memory_cache();
              }
            }
            kvm_faultin_pfn() {
              # 处理 KVM PFN（物理帧号）故障
              __gfn_to_pfn_memslot() {
                # 将 GFN（全局帧号）转换为 PFN（物理帧号）并获取内存插槽
                hva_to_pfn() {
                  # 将 HVA（主机虚拟地址）转换为 PFN（物理帧号）
                  get_user_pages_fast_only() {
                    # 快速获取用户页
                    internal_get_user_pages_fast() {
                      # 内部快速获取用户页
                      lockless_pages_from_mm() {
                        # 从内存管理结构中获取无锁页
                        gup_pgd_range() {
                          # 获取页表项（PGD）范围
                          pud_huge();
                          gup_pmd_range.constprop.0() {
                            # 获取中间页表项（PMD）范围
                            gup_huge_pmd() {
                              # 获取巨大页面的中间页表项
                              try_grab_folio();
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            handle_abnormal_pfn();
            _raw_read_lock();
            is_page_fault_stale();
            kvm_tdp_mmu_map() {
              # TDP MMU 映射
              kvm_mmu_hugepage_adjust() {
                # 调整 KVM MMU 巨大页面
                kvm_mmu_max_mapping_level() {
                  # 获取 KVM MMU 最大映射级别
                  host_pfn_mapping_level();
                }
              }
              __rcu_read_lock();
              tdp_iter_start() {
                # TDP 迭代器开始
                tdp_iter_restart() {
                  # TDP 迭代器重新启动
                  tdp_iter_refresh_sptep();
                }
              }
              disallowed_hugepage_adjust();
              tdp_iter_next() {
                # TDP 迭代器下一个
                tdp_iter_refresh_sptep();
              }
              disallowed_hugepage_adjust();
              tdp_iter_next() {
                # TDP 迭代器下一个
                tdp_iter_refresh_sptep();
              }
            }
            tdp_iter_next() {
              # TDP 迭代器下一个
              tdp_iter_refresh_sptep();
            }
          }
          disallowed_hugepage_adjust();
        }
      }
    }
  }
}

```

![kvm-init-mmu](https://gitee.com/nan-shuaibo/image/raw/master/202403081421893.png)

### MMIO page fault

MMIO是直接将设备I/O映射到物理地址空间内，虚拟机物理内存的虚拟化又是通过EPT机制来完成的， 那么模拟设备的MMIO实现也需要利用EPT机制．虚拟机的EPT页表是在EPT_VIOLATION异常处理的时候建立起来的， 对于模拟设备而言访问MMIO肯定要触发VM_EXIT然后交给QEMU/KVM去处理。其中关于MMIO MMIO page fault的vm exit对应的原因处理函数如下：

```
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
...
  [EXIT_REASON_EPT_MISCONFIG]           = handle_ept_misconfig,
...
};
```

对于上述两种page fault产生的vm exit，`EPT_VIOLATION`表示的是对应的物理页不存在，而`EPT_MISCONFIG`表示EPT页表中有非法的域。

### 挂载点

**EPT page fault：**

| 类型       | 名称               |
| ---------- | ------------------ |
| tracepoint | kvm_page_fault     |
| fexit      | kvm_tdp_page_fault |

**MMIO page fault：**

| 类型       | 名称                   |
| ---------- | ---------------------- |
| fentry     | kvm_mmu_page_fault     |
| tracepoint | handle_mmio_page_fault |

## 示例输出

```
 # sudo ./kvm_watcher -fm               
TIME(ms)           COMM            PID        GPA          COUNT  DELAY(us)  HVA                  PFN               MEM_SLOTID ERROR_TYPE
877831355.823575   CPU 1/KVM       529746     fc096000     1      2.9200     -                    -                 -          Reserved(MMIO)
877831356.426116   CPU 1/KVM       529746     a27c000      1      29.0000    7fcb1607c000         205b6b            10         Write
877831356.478689   CPU 1/KVM       529746     a27d000      1      5.5740     7fcb1607d000         218eb5            10         Write
877831356.779868   CPU 1/KVM       529746     d036640      1      2.8680     7fcb18e36000         b550              10         Exec
877831356.814302   CPU 1/KVM       529746     d015a50      1      3.3680     7fcb18e15000         5977              10         Exec
877831356.851781   CPU 1/KVM       529746     cef0c60      1      3.1390     7fcb18cf0000         15d193            10         Exec
877831356.895407   CPU 1/KVM       529746     d026040      1      3.4770     7fcb18e26000         3188              10         Exec
877831356.945211   CPU 1/KVM       529746     febef000     1      1.7750     -                    -                 -          Reserved(MMIO)
877831357.526563   CPU 1/KVM       529746     da252d0      1      6.8130     7fcb19825000         1c57a8            10         User
877831357.567887   CPU 1/KVM       529746     cef2a72      1      4.0020     7fcb18cf2000         15d19e            10         User
877831365.923055   CPU 0/KVM       529746     a204000      1      36.2550    7fcb16004000         15d1ad            10         Write
877831365.991821   CPU 0/KVM       529746     a205000      1      6.6050     7fcb16005000         189c9b            10         Write
877831366.018521   CPU 0/KVM       529746     a206000      1      4.7600     7fcb16006000         1f3b32            10         Write
877831366.044024   CPU 0/KVM       529746     a207000      1      4.7990     7fcb16007000         1c2335            10         Write
877831366.081925   CPU 0/KVM       529746     cfd8030      1      4.5920     7fcb18dd8000         135be             10         Exec
877831366.118387   CPU 0/KVM       529746     cf7c2f0      1      3.5400     7fcb18d7c000         1766              10         Exec
877831366.151738   CPU 0/KVM       529746     cf7ad00      1      3.0300     7fcb18d7a000         1b943a            10         Exec
877831366.183574   CPU 0/KVM       529746     cf78350      1      2.7500     7fcb18d78000         1b9420            10         Exec
877831367.342812   CPU 0/KVM       529746     b996000      1      12.1780    7fcb17796000         209e26            10         Write
877831367.379176   CPU 0/KVM       529746     b997000      1      5.3060     7fcb17797000         1969b2            10         Write
877831367.420309   CPU 0/KVM       529746     c734dd0      1      4.4100     7fcb18534000         15ae97            10         Exec
877831367.454443   CPU 0/KVM       529746     c733cf0      1      2.9190     7fcb18533000         15ae96            10         Exec
877831369.203014   CPU 0/KVM       529746     febef000     1      3.4450     -                    -                 -          Reserved(MMIO)
877831385.337715   CPU 0/KVM       529746     d054670      1      15.3860    7fcb18e54000         575e              10         Exec
877831400.891921   CPU 0/KVM       529746     d051900      1      14.7630    7fcb18e51000         575b              10         Exec
877831400.951377   CPU 0/KVM       529746     d0502f0      1      3.5300     7fcb18e50000         575a              10         Exec
877831400.983426   CPU 0/KVM       529746     cef1440      1      3.8650     7fcb18cf1000         15d19d            10         Exec
877831401.016302   CPU 0/KVM       529746     cefc7a0      1      3.0840     7fcb18cfc000         15cd9f            10         Exec
877831401.052207   CPU 0/KVM       529746     cee3ed0      1      3.1400     7fcb18ce3000         15e3f1            10         Exec
877831401.162631   CPU 0/KVM       529746     d052077      1      13.8780    7fcb18e52000         575c              10         Exec
877831401.334995   CPU 0/KVM       529746     fc096000     1      3.9740     -                    -                 -          Reserved(MMIO)

```

## 参数介绍

- **TIME(ms)**: 事件发生的时间，以毫秒为单位。
- **COMM**: 触发页面故障的进程名称。
- **PID**: 相应虚拟机进程的标识符（PID）。
- **GPA**: 引发页面故障的访问的客户物理地址（Guest Physical Address）。
- **COUNT**: 相同地址发生页面故障的次数。
- **DELAY(us)**: 处理页面故障所需的时间，以微秒为单位。
- **HVA**: 发生页面故障时被访问的客户虚拟地址（Host Virtual Address）。
- **PFN**: 与页面故障相关联的页帧编号（Page Frame Number）。
- **MEM_SLOTID**: 指示发生页面故障的内存插槽的标识符。
- **ERROR_TYPE**: 页面故障的类型，提供页面故障发生的具体原因。