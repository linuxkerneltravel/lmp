### 一、容器
容器是隔离出来的一组进程，这些进程被限制在一个私有的的根文件系统和进程命名空间内。
容器能够让多个应用同时部署在一台服务器上的多个隔离的环境中，但是这种隔离是伪隔离，容器假装拥有自己独立的操作系统，从而为用户提供一个干净而轻量的Linux环境。
创建容器时，Namespaces负责将容器中的进程隔离在一个单独的环境中，Cgroups负责限制容器能够使用的硬件资源，例如CPU、内存等等。 这样，容器就能像一台单独的虚拟机那样运行，同时也不会滥用宿主机资源，影响其他进程或容器的运行。
业界有很多对容器的实现，如Docker、LXC、Rocket等等。

### 二、LXC和Docker
LXC无需创建完整的虚拟机，而是可以通过自己的进程和网络空间来实现虚拟环境，它使用Namespace来实现进程隔离，同时使用内核自己的Cgroup来解决并限制一个或多个进程中的CPU、内存、磁盘IO和网络使用情况。
我把LXC理解为一种Linux系统提供的技术或者组件（或机制？），可为我们提供轻量级的Linux容器，而Docker是基于容器顶部的单个应用程序的虚拟化。
Docker得益于其基于镜像的部署模型，于是在LXC的基础上还具备可移植、版本控制、快速部署、回滚等能力。

### 三、Namespace
#### 1、定义
首先在task_struct结构体中可以找到关于命名空间成员的定义：
```c
struct task_struct {
    ...
    /* Namespaces: */
	struct nsproxy			*nsproxy;
    ...
}
```

其结构体定义在include/linux/nsproxy.h，如下：
```c
/*
 * A structure to contain pointers to all per-process
 * namespaces - fs (mount), uts, network, sysvipc, etc.
 *
 * The pid namespace is an exception -- it's accessed using
 * task_active_pid_ns.  The pid namespace here is the
 * namespace that children will use.
 *
 * 'count' is the number of tasks holding a reference.
 * The count for each namespace, then, will be the number
 * of nsproxies pointing to it, not the number of tasks.
 *
 * The nsproxy is shared by tasks which share all namespaces.
 * As soon as a single namespace is cloned or unshared, the
 * nsproxy is copied.
 */
struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
	struct cgroup_namespace *cgroup_ns;
};
extern struct nsproxy init_nsproxy;
```
可以看出这个结构体的成员是指向各个命名空间的指针，由于可能有多个进程所在的Namespace完全一样，nsproxy可以在进程间共享，count字段负责记录该结构的引用数，各命名空间解释如下：
- pid-进程号的隔离
- net-网络接口的隔离
- ipc-管理进程间通信的资源
- mnt-管理文件系统挂载点
- uts-(Unix Timesharing System)隔离内核和版本定义（主机名与域名）
- cgroup-5.4把cgroup也集成在namespace中了
由于 user namespace 是和其他 namespace 耦合在一起的，所以没出现在上述结构中。

最后一行是系统预定义的一个初始nsproxy结构，位于/kernel/nsproxy.c中：
```c
struct nsproxy init_nsproxy = {
	.count			= ATOMIC_INIT(1),
	.uts_ns			= &init_uts_ns,
#if defined(CONFIG_POSIX_MQUEUE) || defined(CONFIG_SYSVIPC)
	.ipc_ns			= &init_ipc_ns,
#endif
	.mnt_ns			= NULL,
	.pid_ns_for_children	= &init_pid_ns,
#ifdef CONFIG_NET
	.net_ns			= &init_net,
#endif
#ifdef CONFIG_CGROUPS
	.cgroup_ns		= &init_cgroup_ns,
#endif
};
```
可以看到其中除了mnt_ns为NULL以外，其余均指向系统默认的Namespaces。

/include/linux/nsproxy.h的剩余部分则是这个结构体相关的操作：
```c
int copy_namespaces(unsigned long flags, struct task_struct *tsk);
void exit_task_namespaces(struct task_struct *tsk);
void switch_task_namespaces(struct task_struct *tsk, struct nsproxy *new);
void free_nsproxy(struct nsproxy *ns);
int unshare_nsproxy_namespaces(unsigned long, struct nsproxy **,
	struct cred *, struct fs_struct *);
int __init nsproxy_cache_init(void);

static inline void put_nsproxy(struct nsproxy *ns)
{
	if (atomic_dec_and_test(&ns->count)) {
		free_nsproxy(ns);
	}
}

static inline void get_nsproxy(struct nsproxy *ns)
{
	atomic_inc(&ns->count);
}
```
put_nsproxy用于减少一个nsproxy的引用数;
get_nsproxy用于增加一个nsproxy的引用数。


#### 2、操作函数
1) **clone**
创建一个新的进程并把他放到新的namespace中。
```c
int clone(int (*child_func)(void *), void *child_stack, int flags, void *arg); 
```
flags用于指定一个或者多个命名空间类型（当然也可以包含跟namespace无关的flags，多个flags用|进行分隔），这样就会创建一个或多个新的不同类型的namespace，并把新创建的子进程加入新创建的这些namespace中。
![avatar](./images/namespace-01.jpg)

2) **setns** 
将当前进程加入到已有的namespace中。
```c
int setns(int fd, int nstype); 
```
fd指向/proc/[pid]/ns/目录里相应namespace对应的文件，表示要加入哪个namespace
nstype：指定namespace的类型（上面的任意一个CLONE_NEW*）;

3) **unshare**
使当前进程退出指定类型的namespace，并加入到新创建的namespace（相当于创建并加入新的namespace）。
```c
int unshare(int flags); 
```
flags用于指定一个或者多个命名空间类型（当然也可以包含跟namespace无关的flags，多个flags 用|进行分隔），这样就会创建一个或多个新的不同类型的namespace，并把新创建的子进程加入新创建的这些namespace中。 

**clone和unshare的区别**
clone和unshare的功能都是创建并加入新的namespace，unshare是使当前进程加入新的namespace。clone是创建一个新的子进程，然后让子进程加入新的namespace，而当前进程保持不变。

#### 3、创建过程
系统通过clone来创建一个命名空间，如下：
`int clone(int (*child_func)(void *), void *child_stack, int flags, void *arg);`
ps：fork是进程资源的完全复制，包括进程的PCB、线程的系统堆栈、进程的用户空间、进程打开的设备等，而在clone中其实只有前两项是被复制了的，后两项都与父进程共享。

clone系统调用是对sys_clone的封装，sys_clone中最终调用了do_fork，do_fork中是通过copy_process来复制进程相关信息，关于namespace的部分由copy_namespaces来实现：
```
sys_clone
    do_fork
        _do_fork
            copy_process
                copy_namespaces(clone_flags, p)
                    create_new_namespaces
                        create_nsproxy
                        copy_mnt_ns
                        copy_utsname
                        copy_ipcs
                        copy_pid_ns
                        copy_cgroup_ns
                        copy_net_ns
```
clone_flags可以在sched.h中看到，关于命名空间的有：
```c
...
#define CLONE_NEWNS	        0x00020000	/* New mount namespace group */
...
#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
...
```

copy_namespaces函数定义在/kernel/nsproxy.c中，源码如下：
```c
int copy_namespaces(unsigned long flags, struct task_struct *tsk)
{
	struct nsproxy *old_ns = tsk->nsproxy;
	struct user_namespace *user_ns = task_cred_xxx(tsk, user_ns);
	struct nsproxy *new_ns;

	if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			      CLONE_NEWPID | CLONE_NEWNET |
			      CLONE_NEWCGROUP)))) {
		get_nsproxy(old_ns);
		return 0;
	}

	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * CLONE_NEWIPC must detach from the undolist: after switching
	 * to a new ipc namespace, the semaphore arrays from the old
	 * namespace are unreachable.  In clone parlance, CLONE_SYSVSEM
	 * means share undolist with parent, so we must forbid using
	 * it along with CLONE_NEWIPC.
	 */
	if ((flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) ==
		(CLONE_NEWIPC | CLONE_SYSVSEM)) 
		return -EINVAL;

	new_ns = create_new_namespaces(flags, tsk, user_ns, tsk->fs);
	if (IS_ERR(new_ns))
		return  PTR_ERR(new_ns);

	tsk->nsproxy = new_ns;
	return 0;
}
```
该函数首先检查flags，如果没有指定任何一个需要新建Namespace的flag，直接返回0，反之做相应的权能检查，然后调用create_new_namespaces为进程创建新的Namespace，简要流程如下：
```c
(不是源码，是简略版)
new_nsp = create_nsproxy();

	new_nsp->mnt_ns = copy_mnt_ns(flags, tsk->nsproxy->mnt_ns, user_ns, new_fs);

	new_nsp->uts_ns = copy_utsname(flags, user_ns, tsk->nsproxy->uts_ns);

	new_nsp->ipc_ns = copy_ipcs(flags, user_ns, tsk->nsproxy->ipc_ns);

	new_nsp->pid_ns_for_children = copy_pid_ns(flags, user_ns, tsk->nsproxy->pid_ns_for_children);

	new_nsp->cgroup_ns = copy_cgroup_ns(flags, user_ns, tsk->nsproxy->cgroup_ns);

	new_nsp->net_ns = copy_net_ns(flags, user_ns, tsk->nsproxy->net_ns);

	return new_nsp;
```

### 四、测试
测试程序主要使用clone函数创建新的命名空间，以实现PID和主机名的隔离，代码如下：
```c
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#define STACK_SIZE (1024 * 1024)

static char container_stack[STACK_SIZE];

int container_main(void *args)
{
   printf("I am the bash. \n");
   sethostname("bash",4);
   execv("/bin/bash",args);
}

int main(int args, char *argv[])
{
   printf("The follow bash will be running on a container. \n");
   int container_pid = clone(container_main, container_stack + STACK_SIZE, SIGCHLD | CLONE_NEWUTS | CLONE_NEWPID, NULL);

   waitpid(container_pid, NULL, 0);
   return 0;
}
```

主函数使用**clone**创建新的命名空间，使用参数`CLONE_NEWUTS | CLONE_NEWPID`，调用子程序**container_main**，子程序使用sethostname更改了容器中的主机名，并用execv开启了一个新的bash。
![avatar](./images/namespace-02.jpg)

##namespace相关代码 - 内核5.4

### nsproxy
```c
//include/linux/nsproxy.h, line 31 (as a struct)

struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
	struct cgroup_namespace *cgroup_ns;
};
extern struct nsproxy init_nsproxy;
```
### uts_namespace
```c
//include/linux/utsname.h, line 24 (as a struct)

struct uts_namespace {
	struct kref kref;
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
} __randomize_layout;
extern struct uts_namespace init_uts_ns;
```

### ipc_namespace
```c
//include/linux/ipc_namespace.h, line 29 (as a struct)

struct ipc_namespace {
	refcount_t	count;
	struct ipc_ids	ids[3];

	int		sem_ctls[4];
	int		used_sems;

	unsigned int	msg_ctlmax;
	unsigned int	msg_ctlmnb;
	unsigned int	msg_ctlmni;
	atomic_t	msg_bytes;
	atomic_t	msg_hdrs;

	size_t		shm_ctlmax;
	size_t		shm_ctlall;
	unsigned long	shm_tot;
	int		shm_ctlmni;
	/*
	 * Defines whether IPC_RMID is forced for _all_ shm segments regardless
	 * of shmctl()
	 */
	int		shm_rmid_forced;

	struct notifier_block ipcns_nb;

	/* The kern_mount of the mqueuefs sb.  We take a ref on it */
	struct vfsmount	*mq_mnt;

	/* # queues in this ns, protected by mq_lock */
	unsigned int    mq_queues_count;

	/* next fields are set through sysctl */
	unsigned int    mq_queues_max;   /* initialized to DFLT_QUEUESMAX */
	unsigned int    mq_msg_max;      /* initialized to DFLT_MSGMAX */
	unsigned int    mq_msgsize_max;  /* initialized to DFLT_MSGSIZEMAX */
	unsigned int    mq_msg_default;
	unsigned int    mq_msgsize_default;

	/* user_ns which owns the ipc ns */
	struct user_namespace *user_ns;
	struct ucounts *ucounts;

	struct ns_common ns;
} __randomize_layout;
```

### mnt_namespace
```c
//fs/mount.h, line 8 (as a struct)

struct mnt_namespace {
	atomic_t		count;
	struct ns_common	ns;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
} __randomize_layout;
```

### pid_namespace
```c
//include/linux/pid_namespace.h, line 24 (as a struct)

struct pid_namespace {
	struct kref kref;
	struct idr idr;
	struct rcu_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
#ifdef CONFIG_PROC_FS
	struct vfsmount *proc_mnt;
	struct dentry *proc_self;
	struct dentry *proc_thread_self;
#endif
#ifdef CONFIG_BSD_PROCESS_ACCT
	struct fs_pin *bacct;
#endif
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct work_struct proc_work;
	kgid_t pid_gid;
	int hide_pid;
	int reboot;	/* group exit code if this pidns was rebooted */
	struct ns_common ns;
} __randomize_layout;
extern struct pid_namespace init_pid_ns;
```

### cgroup_namespace
```c
//include/linux/cgroup.h, line 853 (as a struct)

struct cgroup_namespace {
	refcount_t		count;
	struct ns_common	ns;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct css_set          *root_cset;
};
```
### user_namespace
```c
//include/linux/user_namespace.h, line 55 (as a struct)

struct user_namespace {
	struct uid_gid_map	uid_map;
	struct uid_gid_map	gid_map;
	struct uid_gid_map	projid_map;
	atomic_t		count;
	struct user_namespace	*parent;
	int			level;
	kuid_t			owner;
	kgid_t			group;
	struct ns_common	ns;
	unsigned long		flags;

#ifdef CONFIG_KEYS
	/* List of joinable keyrings in this namespace.  Modification access of
	 * these pointers is controlled by keyring_sem.  Once
	 * user_keyring_register is set, it won't be changed, so it can be
	 * accessed directly with READ_ONCE().
	 */
	struct list_head	keyring_name_list;
	struct key		*user_keyring_register;
	struct rw_semaphore	keyring_sem;
#endif

	/* Register of per-UID persistent keyrings for this namespace */
#ifdef CONFIG_PERSISTENT_KEYRINGS
	struct key		*persistent_keyring_register;
#endif
	struct work_struct	work;
#ifdef CONFIG_SYSCTL
	struct ctl_table_set	set;
	struct ctl_table_header *sysctls;
#endif
	struct ucounts		*ucounts;
	int ucount_max[UCOUNT_COUNTS];
} __randomize_layout;

```