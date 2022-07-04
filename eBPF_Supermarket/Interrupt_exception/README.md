# 基本原理
挂载点选择：内核中以下7种异常中断会在触发后会调用同一函数do_error_trap

在中断发生时，内核会通过DEFINE_IDTENTRY宏调用相关中断处理函数，之后调用do_error_trap去唤醒相关线程进行中断处理

0     | #DE    |Divide Error  除0异常      |Fault|NO        |DIV and IDIV
```c
DEFINE_IDTENTRY(exc_divide_error)
{
	do_error_trap(regs, 0, "divide error", X86_TRAP_DE, SIGFPE,
		      FPE_INTDIV, error_get_trap_addr(regs));
}
```
4     | #OF    |Overflow     溢出异常       |Trap |NO        |INTO  instruction  
```c
DEFINE_IDTENTRY(exc_overflow)
{
	do_error_trap(regs, 0, "overflow", X86_TRAP_OF, SIGSEGV, 0, NULL);
}
```
6     | #UD    |Invalid Opcode   无效指令异常   |Fault|NO        |UD2 instruction

```c
static inline void handle_invalid_op(struct pt_regs *regs)
#endif
{
	do_error_trap(regs, 0, "invalid opcode", X86_TRAP_UD, SIGILL,
		      ILL_ILLOPN, error_get_trap_addr(regs));
}

```
9     | ---    |Reserved  协处理器段溢出  |Fault|NO        |                 

```c
DEFINE_IDTENTRY(exc_coproc_segment_overrun)
{
	do_error_trap(regs, 0, "coprocessor segment overrun",
		      X86_TRAP_OLD_MF, SIGFPE, 0, NULL);
}
```
10    | #TS    |Invalid TSS   无效TSS  |Fault|YES       |Task switch or TSS access

```c
DEFINE_IDTENTRY_ERRORCODE(exc_invalid_tss)
{
	do_error_trap(regs, error_code, "invalid TSS", X86_TRAP_TS, SIGSEGV,
		      0, NULL);
}
```
11    | #NP    |Segment Not Present 缺段中断 |Fault|NO        |Accessing segment register 
```c
DEFINE_IDTENTRY_ERRORCODE(exc_segment_not_present)
{
	do_error_trap(regs, error_code, "segment not present", X86_TRAP_NP,
		      SIGBUS, 0, NULL);
}
```
12    | #SS    |Stack-Segment Fault 堆栈异常 |Fault|YES       |Stack operations
```c
DEFINE_IDTENTRY_ERRORCODE(exc_stack_segment)
{
	do_error_trap(regs, error_code, "stack segment", X86_TRAP_SS, SIGBUS,
		      0, NULL);
}
```