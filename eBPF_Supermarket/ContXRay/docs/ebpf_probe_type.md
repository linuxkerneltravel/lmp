
## eBPF系统编程切入点：kprobe的eBPF程序类型、tracepoint的eBPF程序类型

### 1、基本认识
在bpf.h头文件中我们可以看到这样一个枚举类型：
```c
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
};
```
每一个成员都是一个BPF程序类型，其中我们最常用的是KPROBE类型和TRACEPOINT类型，这连中就是我们常说的软件探针方式。
软件探针技术则是通过软件的方式插入探针，捕获软件层次的行为。这些探针技术负责提供数据，上层的Tracing工具和框架则基于这些探针技术来采集数据，并对数据进一步整理、分析、和展现给用户。
Kprobe是一个典型的动态探针，在内核运行时，Kprobe技术将需要监控的内核函数的指令动态替换，使得该函数的控制流跳转到用户自定义的处理函数上。当内核执行到该监控函数时，相应的用户自定义处理函数被执行，然后继续执行正常的代码路径。
Tracepoint是一种典型的静态探针，它通过在内核源代码中插入预先定义的静态钩子函数来实现内核行为的监控。简单地来看，大家可以把Tracepoint的原理等同于调试程序时加入的printf函数。

### 2、实现机制以及原理分析
1. **使用场景**：
    在函数入口放置动态或静态追踪点，多用于功能跟踪与性能测试等。
    <br>
2. **Hook 位置**：
    BPF程序是在内核态或者用户态插入hook点来执行，即在预设的或者自设的hook点挂载上BPF程序，当hook点事件发生的时候BPF程序也得以执行，之后BPF程序会返回hook点预定义的值，内核会根据返回值决定如何进行下一步操作。
    预置好的hook点有函数入口出口处、系统调用、网络事件、内核追踪点等，如果预置的hook点无法满足需求，也可以通过kprobe放置动态跟踪点，或者tracepoint放置静态追踪点。
    <br>
3. **参数**：
    上一小节中我们在枚举类型bpf_prog_type中可以看到，其中的每一个成员都是一个BPF程序类型，而我们最常用的是KPROBE类型和TRACEPOINT类型。  
    Kprobe为内核探针，可以动态地跟踪大多数内核函数调用，我们可以直接声明一个有`kprobe__`前缀的函数，如下：  
    `int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {}`  
    或者也可以声明一个普通的C函数，再使用Python BPF中的attach_kprobe()来把自定义C函数与内核函数关联起来，如下：  
    `void do_read(struct pt_regs *ctx) {}`  
    `b.attach_kprobe(event="vfs_read", fn_name="do_read")`  

    可以看到传入参数`struct pt_regs *regs`，源码中结构体pt_regs定义如下：
    ```c
    struct pt_regs { 
        long ebx;
        long ecx;
        long edx;
        long esi; 
        long edi; 
        long ebp; 
        long eax; 
        int xds; 
        int xes; 
        long orig_eax; 
        long eip; 
        int xcs; 
        long eflags; 
        long esp; 
        int xss; 
    };
     ```
    官方文档中称这个参数为寄存器和BPF上下文，提供了访问内核正在处理的信息。换言之这个结构保存的是在内核入口中所必需的状态信息，比如说每一次的系统调用、中断、陷阱、故障等的现场信息。但是我们不必担心要如何去访问这些寄存器，因为内核提供了相应的宏可以进行访问。

    而第二个参数则是需要与所探测的内核函数的参数保持一致，如在上述示例中`struct sock *sk`就是内核函数`tcp_v4_connect`的同名参数，但是如果没有使用该内核函数参数的需求的话，第二个参数处也可以不进行设置。
    <br>
4. **加载方式**：
    以kprobe为例，在kprobe创建时会产生一个对应的ID，存储在/sys/kernel/debug/tracing/events/kprobes/[probe名称]/id文件中，然后用该ID打开一个perf事件将其启用，并将该perf事件的BPF程序设置为自定义的程序，当启用探针并命中断点时，kprobe_perf_func函数通过执行trace_call_bpf附加到探针点的BPF程序。
    tracepoint同理，启用并命中跟踪点后，perf_trace_将调用perf_trace_run_bpf_submit，该函数同样通过trace_call_bpf调用bpf程序。
    <br>
5. **kprobe机制、tracepoint原理分析**:
    1）Kprobe是一种内核调试技术，它可以在任意的位置放置探测点，它提供了探测点的调用前、调用后和访问出错3种回调方式，分别是pre_handler、post_handler和fault_handler：
    - pre_handler函数将在被探测指令被执行前回调；
    - post_handler会在被探测指令执行完毕后回调；
    - fault_handler会在内存访问出错时被调用。
    Kprobe的工作过程大致如下：
    1）注册kprobe：注册的每个kprobe对应一个kprobe结构体，该结构体记着插入点以及该插入点本来对应的指令original_opcode；
    2）替换原有指令：能kprobe的时候将插入点位置的指令替换为一条异常（BRK）指令，这样当CPU执行到此处就会陷入到异常态；
    3）执行pre_handler：进入异常态后，首先执行pre_handler，然后利CPU提供的单步调试（single-step）功能，设置好相应的寄存器，将下一指令设置为插入点处本来的指令，从异常态返回；
    4）再次陷入异常态，上一步骤中设置了single-step相关的寄存器，所original_opcode刚一执行，便会再次陷入异常态，此时将signle-step除，并且执行post_handler，然后从异常态安全返回。
    
    2）Tracepoint是采用“插桩”的方式，即在函数中埋下一个追踪点，在运行函数时就会调用相对应的探针。每种探测点有一个名称、一个控制该追踪点的开关（当跟踪点处于“关闭”状态时，它没有任何作用，只增加微小的时间损失（检查分支的条件）和空间损失。当跟踪点为“ 打开”时，每次在调用者的执行上下文中执行跟踪点时，都会调用相连接的探针。探针函数执行完后，将返回到调用方）、桩函数（每个桩函数实现不同的debug功能）以及桩函数的注册和卸载函数。
    追踪点一次执行各个桩函数，并把追踪结果如进程信息、地址信息、栈信息等保存至一个环形队列（ring buffer）中，这个缓冲区的信息通过debugfs的形式呈递给用户态。


### 3、kprobe机制与“eBPF的Map机制”结合(kprobe类型的eBPF程序类型)

#### 3.1 什么是eBPF的Map

eBPF map是一个通用的数据结构，也称作映射表，用以存储不同类型的数据，提供了用户态和内核态数据交互、数据存储、多程序共享数据等功能。用户进程可以创建多个map并通过文件描述符（fd）访问它们，不同的eBPF程序可以并行访问相同的map，用户进程和eBPF程序可以决定他们在map中存储的内容。
Map映射表支持多种映射方式，其类型可以在/tools/bpf/bpftool/map.c查询到，如下：
```c
const char * const map_type_name[] = {
	[BPF_MAP_TYPE_UNSPEC]			= "unspec",
	[BPF_MAP_TYPE_HASH]			= "hash",
	[BPF_MAP_TYPE_ARRAY]			= "array",
	[BPF_MAP_TYPE_PROG_ARRAY]		= "prog_array",
	[BPF_MAP_TYPE_PERF_EVENT_ARRAY]		= "perf_event_array",
	[BPF_MAP_TYPE_PERCPU_HASH]		= "percpu_hash",
	[BPF_MAP_TYPE_PERCPU_ARRAY]		= "percpu_array",
	[BPF_MAP_TYPE_STACK_TRACE]		= "stack_trace",
	[BPF_MAP_TYPE_CGROUP_ARRAY]		= "cgroup_array",
	[BPF_MAP_TYPE_LRU_HASH]			= "lru_hash",
	[BPF_MAP_TYPE_LRU_PERCPU_HASH]		= "lru_percpu_hash",
	[BPF_MAP_TYPE_LPM_TRIE]			= "lpm_trie",
	[BPF_MAP_TYPE_ARRAY_OF_MAPS]		= "array_of_maps",
	[BPF_MAP_TYPE_HASH_OF_MAPS]		= "hash_of_maps",
	[BPF_MAP_TYPE_DEVMAP]			= "devmap",
	[BPF_MAP_TYPE_DEVMAP_HASH]		= "devmap_hash",
	[BPF_MAP_TYPE_SOCKMAP]			= "sockmap",
	[BPF_MAP_TYPE_CPUMAP]			= "cpumap",
	[BPF_MAP_TYPE_XSKMAP]			= "xskmap",
	[BPF_MAP_TYPE_SOCKHASH]			= "sockhash",
	[BPF_MAP_TYPE_CGROUP_STORAGE]		= "cgroup_storage",
	[BPF_MAP_TYPE_REUSEPORT_SOCKARRAY]	= "reuseport_sockarray",
	[BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE]	= "percpu_cgroup_storage",
	[BPF_MAP_TYPE_QUEUE]			= "queue",
	[BPF_MAP_TYPE_STACK]			= "stack",
	[BPF_MAP_TYPE_SK_STORAGE]		= "sk_storage",
};
```

#### 3.2 简单了解eBPF的Map的操作
在文件/include/uapi/linux/bpf.h中有以下定义：
```c
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
    ...
};
```
可以看到eBPF map除了创建操作`bpf_map_create`以外，还有遍历、更新、查找、删除等操作，如下：
- 查询： bpf_map_lookup_elem(int fd, const void *key, void *value);
- 更新： bpf_map_update_elem(int fd, const void *key, const void *value,__u64 flags);
- 删除： bpf_map_delete_elem(int fd, const void *key);
- 遍历： bpf_map_get_next_key(int fd, const void *key, void *next_key);
其更多操作以及函数原型可以在/tools/lib/bpf/bpf.h查到。

#### 3.3 “kprobe机制本身“与“kprobe的eBPF程序类型”对比
首先eBPF程序的优势在于它可以将特定的数据复制到用户态，这样可以很好地避免将事件的全部数据复制到用户空间而产生过大的性能开销。
其次kprobes类eBPF程序可以动态跟踪众多内核函数，从而能够提取内核绝大部分信息，但是由于和kprobes机制的结合带来的不稳定性会影响eBPF程序自身的稳定性。
最后虽然kprobe机制可以通过加载内核模块的方式来采集数据到用户态，但是通过加载内核模块的无法检测出一些恶意bug和安全漏洞，而BPF程序首先需要经过验证器进行安全验证，防止出现反复查漏甚至是系统崩溃的情况。此外，进行内核开发需要具备大量的知识储备，而BPF编程如今有很成熟的前端框架，例如BCC可以支持多种编程语言的开发环境，对于新手上手而言更加友好。

#### 3.4 krpobe机制与eBPF的MAP结合带来的优势
首先，相对于传统的cBPF将整个通信报文从内核空间复制到用户空间的开销，通过krpobe追踪到特定的数据后，再经由MAP机制映射到用户态的方式会大大减少系统开销，提高性能和效率。
其次，由于eBPF的利用范围非常广（如性能调优、内核监控、流量控制等各种应用场景），而eBPF程序的MAP机制提供了丰富的数据结构支持，因此它可以解决通信数据的多样性问题。


### 4、kprobe内核模块编程具体实例
这里以samples\kprobes\kprobe_example.c为例来解释一下：
```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

/* 首先每个探针程序都需要分配一块kprobe结构 */
static struct kprobe kp = {
	.symbol_name	= "do_fork",    
    //.symbol_name表示探测的内核函数为do_fork
};

/*前置方法handler_pre，该回调函数的第一个入参是注册的struct kprobe探测实例，第二个参数是保存的触发断点前的寄存器状态，它在do_fork函数被调用之前被调用，该函数仅仅是打印了被探测点的地址，保存的个别寄存器参数*/
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	printk(KERN_INFO "pre_handler: p->addr = 0x%p, ip = %lx,"
			" flags = 0x%lx\n",
		p->addr, regs->ip, regs->flags);
	return 0;
}

/*后置方法handler_post，该回调函数的前两个入参同handler_pre，第三个参数目前尚未使用，全部为0；该函数在do_fork函数调用之后被调用，这里打印的内容同handler_pre类似。*/
static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
	printk(KERN_INFO "post_handler: p->addr = 0x%p, flags = 0x%lx\n",
		p->addr, regs->flags);
}

/*执行失败方法handler_fault，该回调函数会在执行handler_pre、handler_post或单步执行do_fork时出现错误时调用，这里第三个参数时具体发生错误的trap number，与架构相关，例如i386的page fault为14*/
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr);
	/* 不需处理，于是返回 */
	return 0;
}

/*加载内核模块*/
static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;

    //注册kprobe
	ret = register_kprobe(&kp); 
	if (ret < 0) {
		printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
	return 0;
}

/*退出内核模块*/
static void __exit kprobe_exit(void)
{
	//注销kprobe
    unregister_kprobe(&kp);  
	printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
```
