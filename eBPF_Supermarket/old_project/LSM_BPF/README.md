#### 编写LSM BPF 类型的BPF程序



##### 基本介绍

 LSM BPF，是BPF函数31种程序类型中的一种，其前身为KSRI（内核运行时安全检测），这个项目的动机是寻找更容易、更快地减轻Linux系统在运行时受到的持续攻击的方法，也有利于当前希望能在内核里面做过滤或阻断又担心如此带来的稳定性问题。如果只是把阻断和过滤的事情放在应用层，很多CNCF的开源项目都已经实现了，如Falco、Tetragon、Tracee等项目，但在应用层做监测和阻断的时机和速度，比在内核层的效果就差很多，如此一来就有了KRSI，“内核运行时安全检测”，通过eBPF + LSM结合的形式可以探索更多的可行性，至于稳定性问题由Verifier兜底，挂了也不会影响内核的运行。



 LSM BPF的使用和其他的eBPF程序类似，最主要的区别是LSM BPF需要挂钩在LSM提供的hook点上。

要编写LSM BPF程序，第一步是对LSM有所了解。



##### 编写一个LSM

最初的LSM以内核模块的形式存在，2.6版本以后不再支持模块方式加入内核，LSM必须与内核一同编译。

下面是一段示例：

```
#include<linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/sysctl.h>
#include <linux/ptrace.h>
#include <linux/prctl.h>
#include <linux/ratelimit.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>

//实现接口
int test_file_permission(struct file *file, int mask)
{
    char *name = file->f_path.dentry->d_name.name;
    if(!strcmp(name, "test.txt"))
    {
        file->f_flags |= O_RDONLY;
        printk("========== you can have your control code here!\n");
    }
    return 0;
}

//定义 security_hook_list 数组，security_hook_list 记录单个接口的信息，然后模块初始化函数中会调用 security_add_hooks 将 security_hook_list 数组链接到上面的 security_hook_heads 上。

//security_hook_list 的赋值是通过 LSM_HOOK_INIT 宏，调用为 LSM_HOOK_INIT(接口, 接口实现)，会赋值 head 和 hook 成员变量，lsm 实际上没有使用，list 会在 security_add_hooks 函数中链接起来。

static struct security_hook_list test_security_ops[] = {
    LSM_HOOK_INIT(file_permission, test_file_permission),
};

static __init test_init(void)
{
    printk("========== enter test init!\n");
    //通过security_add_hooks 函数将访问控制模块接口添加到 LSM，hooks 为该模块定义的接口数组，count 为数组大小，lsm 为模块名字。
    security_add_hooks(test_security_ops, ARRAY_SIZE(test_security_ops), "demo");
}

security_initcall(test_init);
```

这是4.2版本以后LSM的样子，在这之前，LSM Hook Function被保存在内核内存的一个全局数组security_operations（定义在原本的include/linux/security.h）中。（具体内容查看commit b1d9e6b0646d0e5ee5d9050bd236b6c65d66faef）。

这段程序实现了一个test_file_permission，然后将该函数挂到“file_permission”接口，file_permission就是LSM提供的一个LSM HOOK，在include\linux\lsm_hooks.h 中可以找到这些hook点。

 

```
struct security_hook_list {
	struct hlist_node		list;   //链表组织
	struct hlist_head		*head;	//链表头
	union security_list_options	hook;  //security_list_options定义hook
	char				*lsm;
} __randomize_layout;
```



```
union security_list_options {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) RET (*NAME)(__VA_ARGS__);
	#include "lsm_hook_defs.h"
	#undef LSM_HOOK
};
```

security_list_options中列出了所以LSM HOOK点。

```
/**
 * union security_list_options - Linux Security Module hook function list
 *
 * Security hooks for program execution operations.
```

以file_permission为例：

```
 * @file_permission:
 *	Check file permissions before accessing an open file.  This hook is
 *	called by various operations that read or write files.  A security
 *	module can use this hook to perform additional checking on these
 *	operations, e.g.  to revalidate permissions on use to support privilege
 *	bracketing or policy changes.  Notice that this hook is used when the
 *	actual read/write operations are performed, whereas the
 *	inode_security_ops hook is called when a file is opened (as well as
 *	many other operations).
 *	Caveat:  Although this hook can be used to revalidate permissions for
 *	various system call operations that read or write files, it does not
 *	address the revalidation of permissions for memory-mapped files.
 *	Security modules must handle this separately if they need such
 *	revalidation.
```

LSM根据上述提供的HOOK点的种类提供了不同的结体，通过这些结构体获取相应的数据。

```
struct linux_binprm; // 程序
struct cred; // 进程相关数据结构
struct rlimit; // 进程相关数据结构
struct siginfo; // 信号
struct sembuf; // 信号量
struct kern_ipc_perm; // Semaphore信号，共享内存段，或者消息队列
struct audit_context; // 审计
struct super_block; // 文件系统
struct inode; // 管道，文件，或者Socket套接字
struct dentry; // 与文件相关的目录项对象，指向相关目录项的指针
struct file; // 文件系统相关数据结构
struct vfsmount; // 文件系统相关数据结构
struct path; // 文件路径
struct qstr; // 是一个内核字符串的包装器，它存储了实际的char*字符串以及字符串长度和散列值，这使得更容易处理查找工作。 要注意的是，这里并不存储绝对路径，而是只有路径的最后一个分量，例如对/usr/bin/emacs只存储emacs，因为在linux中，路径信息隐含在了dentry层次链表结构中了 
struct iattr; // inode相关
struct fown_struct; // 该结构的作用是通过信号进行I/O时间通知的数据
struct file_operations; // 指向文件操作表的指针， 定义在linux/include/linux/fs.h中，其中包含着与文件关联的操作
struct msg_msg; // 单个的消息
struct xattr; // 文件系统扩展属性
struct xfrm_sec_ctx; //  安全上下文, 加密时使用。
struct mm_struct; // 进程地址空间
struct fs_context;
struct fs_parameter;
enum fs_value_type;
struct watch;
struct watch_notification;
```

以linux_binprm为例：

```
/*
 * This structure is used to hold the arguments that are used when loading binaries.
 */
struct linux_binprm {
#ifdef CONFIG_MMU
	struct vm_area_struct *vma;
	unsigned long vma_pages;
#else
# define MAX_ARG_PAGES	32
	struct page *page[MAX_ARG_PAGES];
#endif
	struct mm_struct *mm;
	unsigned long p; /* current top of mem */
	unsigned long argmin; /* rlimit marker for copy_strings() */
	unsigned int
		/* Should an execfd be passed to userspace? */
		have_execfd:1,

		/* Use the creds of a script (see binfmt_misc) */
		execfd_creds:1,
		/*
		 * Set by bprm_creds_for_exec hook to indicate a
		 * privilege-gaining exec has happened. Used to set
		 * AT_SECURE auxv for glibc.
		 */
		secureexec:1,
		/*
		 * Set when errors can no longer be returned to the
		 * original userspace.
		 */
		point_of_no_return:1;
#ifdef __alpha__
	unsigned int taso:1;
#endif
	struct file *executable; /* Executable to pass to the interpreter */
	struct file *interpreter;
	struct file *file;
	struct cred *cred;	/* new credentials */
	int unsafe;		/* how unsafe this exec is (mask of LSM_UNSAFE_*) */
	unsigned int per_clear;	/* bits to clear in current->personality */
	int argc, envc;
	const char *filename;	/* Name of binary as seen by procps */
	const char *interp;	/* Name of the binary really executed. Most
				   of the time same as filename, but could be
				   different for binfmt_{misc,script} */
	const char *fdpath;	/* generated filename for execveat */
	unsigned interp_flags;
	int execfd;		/* File descriptor of the executable */
	unsigned long loader, exec;

	struct rlimit rlim_stack; /* Saved RLIMIT_STACK used during exec. */

	char buf[BINPRM_BUF_SIZE];
} __randomize_layout;
```



##### 编写LSM BPF 程序





```
int file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot);
```



```
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include  <errno.h>



SEC("lsm/file_mprotect")//file_mprotect是LSM hook点
int BPF_PROG(mprotect_audit, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)//mprotect_audit是 eBPF 程序的名称
{
        /* ret is the return value from the previous BPF program
         * or 0 if it's the first hook.
         */
        if (ret != 0)
                return ret;

        int is_heap;

        is_heap = (vma->vm_start >= vma->vm_mm->start_brk &&
                   vma->vm_end <= vma->vm_mm->brk);

        /* Return an -EPERM or write information to the perf events buffer
         * for auditing
         */
        if (is_heap)
                return -EPERM;
}
```



LSM BPF 程序的加载和其他BPF程序类似，可以通过BPF_PROG_LOAD加载：

```
struct bpf_object *obj;

obj = bpf_object__open("./my_prog.o");
bpf_object__load(obj);
```





附录：

```
commit b1d9e6b0646d0e5ee5d9050bd236b6c65d66faef
Author: Casey Schaufler <casey@schaufler-ca.com>
Date: Sat May 2 15:11:42 2015 -0700

LSM: Switch to lists of hooks

Instead of using a vector of security operations with explicit, special case stacking of the capability and yama hooks use lists of hooks with capability and yama hooks included as appropriate.

The security_operations structure is no longer required.
Instead, there is a union of the function pointers that allows all the hooks lists to use a common mechanism for list management while retaining typing. Each module supplies an array describing the hooks it provides instead of a sparsely populated security_operations structure.
The description includes the element that gets put on the hook list, avoiding the issues surrounding individual element allocation.

The method for registering security modules is changed to reflect the information available. The method for removing a module, currently only used by SELinux, has also changed.
It should be generic now, however if there are potential race conditions based on ordering of hook removal that needs to be addressed by the calling module.

The security hooks are called from the lists and the first failure is returned.
```








