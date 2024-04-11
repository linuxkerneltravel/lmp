# 中断异常
Interrupt Exception一般发生在指令执行时，由CPU控制单元产生，在一条指令终止执行后CPU发出中断，而不是发生在代码指令执行期间,比如系统调用。当一个异常发生时内核向引起异常的进程发送一个信号通知一个反常条件。

## 中断异常处理程序更新时机

### 体系结构相关的中断初始化:setup_arch()
在start_kernel中调用setup_arch对不同架构进行不同初始化，每个结构都有一个setup_arch函数
> init/main.c
```c
asmlinkage __visible void __init start_kernel(void)
{
       ……
    setup_arch(&command_line);

    trap_init(); // 初始化异常表预留vector
       ……
}
```
setup_arch关于中断部分初始化实际上是更新前32个异常中的X86_TRAP_DB(1号, 用于debug)、X86_TRAP_BP(3号, 用于debug时的断点)和X86_TRAP_PF 缺页异常的中断处理程序。
> arch/x86/kernel/setup.c
```c
void __init setup_arch(char **cmdline_p)
{
    ......
    idt_setup_early_traps();
    ......
    idt_setup_early_pf();
    ......
}
```
**idt_setup_early_traps:**
使用early_idts更新idt_table中X86_TRAP_DB X86_TRAP_BP的中断处理程序
```c
static const __initconst struct idt_data early_idts[] = {
	INTG(X86_TRAP_DB,		asm_exc_debug),
	SYSG(X86_TRAP_BP,		asm_exc_int3),

#ifdef CONFIG_X86_32
	INTG(X86_TRAP_PF,		asm_exc_page_fault),
#endif
};
```
```c
void __init idt_setup_early_traps(void)
{
	idt_setup_from_table(idt_table, early_idts, ARRAY_SIZE(early_idts),
			     true);
	load_idt(&idt_descr);
}
```

**idt_setup_early_pf:**
使用early_pf_idts更新idt_table中X86_TRAP_PF 缺页异常的中断处理程序
```c
static const __initconst struct idt_data early_pf_idts[] = {
	INTG(X86_TRAP_PF,		asm_exc_page_fault),
};
```
```c
void __init idt_setup_early_pf(void)
{
	idt_setup_from_table(idt_table, early_pf_idts,
			     ARRAY_SIZE(early_pf_idts), true);
}
```
## 更新部分异常中断处理程序:trap_init()
在start_kernel()中调用trap_init()
> init/main.c
```c
asmlinkage __visible void __init start_kernel(void)
{
    ......
    trap_init(); // 初始化异常表预留vector
    ......
}
```
trap_init调用idt_setup_traps更新部分异常的中断处理程序
```c
void __init trap_init(void)
{
    ......

	idt_setup_traps();
    ......
    idt_setup_ist_traps();
    ......
}
```
**idt_setup_traps():**
使用def_idts更新idt_table中X86_TRAP_DB X86_TRAP_BP的中断处理程序
```c
static const __initconst struct idt_data def_idts[] = {
	INTG(X86_TRAP_DE,		asm_exc_divide_error),
	INTG(X86_TRAP_NMI,		asm_exc_nmi),
	INTG(X86_TRAP_BR,		asm_exc_bounds),
	INTG(X86_TRAP_UD,		asm_exc_invalid_op),
	INTG(X86_TRAP_NM,		asm_exc_device_not_available),
	INTG(X86_TRAP_OLD_MF,		asm_exc_coproc_segment_overrun),
	INTG(X86_TRAP_TS,		asm_exc_invalid_tss),
	INTG(X86_TRAP_NP,		asm_exc_segment_not_present),
	INTG(X86_TRAP_SS,		asm_exc_stack_segment),
	INTG(X86_TRAP_GP,		asm_exc_general_protection),
	INTG(X86_TRAP_SPURIOUS,		asm_exc_spurious_interrupt_bug),
	INTG(X86_TRAP_MF,		asm_exc_coprocessor_error),
	INTG(X86_TRAP_AC,		asm_exc_alignment_check),
	INTG(X86_TRAP_XF,		asm_exc_simd_coprocessor_error),

#ifdef CONFIG_X86_32
	TSKG(X86_TRAP_DF,		GDT_ENTRY_DOUBLEFAULT_TSS),
#else
	INTG(X86_TRAP_DF,		asm_exc_double_fault),
#endif
	INTG(X86_TRAP_DB,		asm_exc_debug),

#ifdef CONFIG_X86_MCE
	INTG(X86_TRAP_MC,		asm_exc_machine_check),
#endif

	SYSG(X86_TRAP_OF,		asm_exc_overflow),
#if defined(CONFIG_IA32_EMULATION)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_compat),
#elif defined(CONFIG_X86_32)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_32),
#endif
};
```
```c
void __init idt_setup_traps(void)
{
	idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}
```
**idt_setup_ist_traps()：**
重新初始化一些异常中断让他们使用IST(Interrupt Stack Table)。Linux Kernel支持7个IST，可以通过tss.ist[]访问。X86_TRAP_DB、X86_TRAP_NMI、X86_TRAP_DF、X86_TRAP_MC、X86_TRAP_VC就是tss.ist[]的索引。
```c
static const __initconst struct idt_data ist_idts[] = {
	ISTG(X86_TRAP_DB,	asm_exc_debug,			IST_INDEX_DB),
	ISTG(X86_TRAP_NMI,	asm_exc_nmi,			IST_INDEX_NMI),
	ISTG(X86_TRAP_DF,	asm_exc_double_fault,		IST_INDEX_DF),
#ifdef CONFIG_X86_MCE
	ISTG(X86_TRAP_MC,	asm_exc_machine_check,		IST_INDEX_MCE),
#endif
#ifdef CONFIG_AMD_MEM_ENCRYPT
	ISTG(X86_TRAP_VC,	asm_exc_vmm_communication,	IST_INDEX_VC),
#endif
};
```
```c
/**
 * idt_setup_ist_traps - Initialize the idt table with traps using IST
 */
void __init idt_setup_ist_traps(void)
{
	idt_setup_from_table(idt_table, ist_idts, ARRAY_SIZE(ist_idts), true);
}
```



```c
/**
 * idtentry_mce_db - Macro to generate entry stubs for #MC and #DB
 * @vector:		Vector number
 * @asmsym:		ASM symbol for the entry point
 * @cfunc:		C function to be called
 *
 * The macro emits code to set up the kernel context for #MC and #DB
 *
 * If the entry comes from user space it uses the normal entry path
 * including the return to user space work and preemption checks on
 * exit.
 *
 * If hits in kernel mode then it needs to go through the paranoid
 * entry as the exception can hit any random state. No preemption
 * check on exit to keep the paranoid path simple.
 */
.macro idtentry_mce_db vector asmsym cfunc
SYM_CODE_START(\asmsym)
	UNWIND_HINT_IRET_REGS
	ASM_CLAC

	pushq	$-1			/* ORIG_RAX: no syscall to restart */

	/*
	 * If the entry is from userspace, switch stacks and treat it as
	 * a normal entry.
	 */
	testb	$3, CS-ORIG_RAX(%rsp)
	jnz	.Lfrom_usermode_switch_stack_\@

	/* paranoid_entry returns GS information for paranoid_exit in EBX. */
	call	paranoid_entry

	UNWIND_HINT_REGS

	movq	%rsp, %rdi		/* pt_regs pointer */

	call	\cfunc

	jmp	paranoid_exit

	/* Switch to the regular task stack and use the noist entry point */
.Lfrom_usermode_switch_stack_\@:
	idtentry_body noist_\cfunc, has_error_code=0

_ASM_NOKPROBE(\asmsym)
SYM_CODE_END(\asmsym)
.endm
```


## exception处理

以divide_error异常为例,初始化时注册函数为asm_exc_divide_error
```c
static const __initconst struct idt_data def_idts[] = {
	INTG(X86_TRAP_DE,		asm_exc_divide_error),
    ......
};
```
展开后为：
```c
{
		.vector = 0,
		.bits.ist = 0,
		.bits.type = GATE_INTERRUPT,
		.bits.dpl = 0x0,
		.bits.p = 1,
		.addr = asm_exc_divide_error,
		.segment = (2 * 8),
	},
```
函数声明：
```c
DECLARE_IDTENTRY(X86_TRAP_DE,		exc_divide_error);
```
展开后为：
```c
#define DECLARE_IDTENTRY(vector, func)					\
	asmlinkage void asm_##func(void);				\
	asmlinkage void xen_asm_##func(void);				\
	__visible void func(struct pt_regs *regs)

void asm_exc_divide_error(void);
void xen_asm_exc_divide_error(void);
void exc_divide_error(struct pt_regs *regs);
```
触发异常后会执行下面exc_divide_error，最后调用到do_error_trap向进程发送一个异常信号
```c
DEFINE_IDTENTRY(exc_divide_error)
{
	do_error_trap(regs, 0, "divide error", X86_TRAP_DE, SIGFPE,
		      FPE_INTDIV, error_get_trap_addr(regs));
}
```