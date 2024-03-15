

vm exit（EPT_VIOLATION）处理流程：

```
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
...
	[EXIT_REASON_EPT_VIOLATION]	      = handle_ept_violation,
...
};

```

```c
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