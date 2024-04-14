## Linux Namespace

### 一.介绍

Linux Namespace提供了一种内核级别隔离系统资源的方法。每个namespace的目的是将特定的全局系统资源包装在一个抽象中，使namespace内的进程看起来拥有自己的全局资源隔离实例。隔离意味着可以抽象出多个轻量级的“内核”（容器进程），这些进程可以充分利用宿主机的资源，宿主机有的资源容器进程都可以享有，但彼此之间是隔离的。

命名空间的总体目标之一是支持容器的实现，[容器](https://lwn.net/Articles/524952/)是一种用于轻量级虚拟化的工具，它为一组进程提供了它们是系统上唯一进程的错觉。Docker正是使用namespace提供容器的隔离工作空间。目前，Linux 实现了六种不同类型的命名空间:

| 分类                   | 系统调用参数    | 描述                 |
| ---------------------- | --------------- | -------------------- |
| **Mount namespaces**   | CLONE_NEWNS     | 隔离文件系统挂载点   |
| **UTS namespaces**     | CLONE_NEWUTS    | 隔离主机名           |
| **IPC namespaces**     | CLONE_NEWIPC    | 隔离进程间通信       |
| **PID namespaces**     | CLONE_NEWPID    | 隔离进程的ID         |
| **Network namespaces** | CLONE_NEWNET    | 隔离网络资源         |
| **User namespaces**    | CLONE_NEWUSER   | 隔离用户和用户组的ID |
| **Time namespace**     | CLONE_NEWTIME   | 隔离时钟             |
| **Cgroup namespace**   | CLONE_NEWCGROUP | 隔离Cgroup           |

#### 与namespace有关的系统调用


```c
int clone(int (*child_func)(void *), void *child_stack, int flags, void *arg);
```

通过`flags`参数来控制创建进程时的特性，比如新创建的进程是否与父进程共享虚拟内存等。比如可以传入`CLONE_NEWNS`标志使得新创建的进程拥有独立的`Mount Namespace`，也可以传入多个flags使得新创建的进程拥有多种特性，比如：

```c
flags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC;
```

传入这个flags那么新创建的进程将同时拥有独立的`Mount Namespace`、`UTS Namespace`和`IPC Namespace`。

除了`clone()`外,还可以通过以下两个系统调用改变进程的namespace:

- `unshare()` 

```c
int unshare(int flags);
```
unshare系统调用可以使进程脱离到新的Namespace.不用关联之前存在的Namespace，只需要指定需要分离的Namespace就行，该调用会自动创建一个新的Namespace。`flags`用于指明要分离的资源类别，它支持的`flags`与`clone`系统调用支持的`flags`类似


- `setns()` 

```c
int setns(int fd, int nstype);
```
该函数可以把进程加入到指定的Namespace中

`fd`参数表示文件描述符，`fd`会关联到某个namespace

`nstype`参数,用来检查`fd`关联`Namespace`是否与`nstype`表明的`Namespace`一致，如果填0的话表示不进行该项检查。

#### 查看进程所属的namespace

在`/proc/[PID]/ns`下,通过`ls -al`命令,可以查看某个进程所属的namespace

```
root@VM-16-3-ubuntu:/proc/1501936/ns# ll
total 0
dr-x--x--x 2 root root 0 Apr 16 22:56 ./
dr-xr-xr-x 9 root root 0 Apr 16 22:56 ../
lrwxrwxrwx 1 root root 0 Apr 18 15:06 cgroup -> 'cgroup:[4026531835]'
lrwxrwxrwx 1 root root 0 Apr 18 15:06 ipc -> 'ipc:[4026532315]'
lrwxrwxrwx 1 root root 0 Apr 18 15:06 mnt -> 'mnt:[4026532313]'
lrwxrwxrwx 1 root root 0 Apr 16 22:56 net -> 'net:[4026532318]'
lrwxrwxrwx 1 root root 0 Apr 18 15:06 pid -> 'pid:[4026532316]'
lrwxrwxrwx 1 root root 0 Apr 18 15:09 pid_for_children -> 'pid:[4026532316]'
lrwxrwxrwx 1 root root 0 Apr 18 15:09 time -> 'time:[4026531834]'
lrwxrwxrwx 1 root root 0 Apr 18 15:09 time_for_children -> 'time:[4026531834]'
lrwxrwxrwx 1 root root 0 Apr 18 15:06 user -> 'user:[4026531837]'
lrwxrwxrwx 1 root root 0 Apr 18 15:06 uts -> 'uts:[4026532314]'
```

`4026531835`代表namespace的id,若两个进程的id相同,则代表同属于一个namespace.

### 二、基于namespace编写简易容器

#### 功能目标

- 隔离文件系统挂载点（仅proc）
- 隔离进程ID
- 隔离主机名
- 隔离用户（组）ID

#### 主程序

- 创建容器进程：

```c
#define STACK_SIZE (1024 * 1024)
static char container_stack[STACK_SIZE];

int main(){
    ...
	int container_pid = clone(container_main, container_stack+STACK_SIZE, 
            	CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER | SIGCHLD, NULL);
    ...
}
```

- 映射uid/gid： 

```c
void set_map(char* file, int inside_id, int outside_id, int len) {
    FILE* mapfd = fopen(file, "w");
    if (NULL == mapfd) {
        perror("open file error");
        return;
    }
    fprintf(mapfd, "%d %d %d", inside_id, outside_id, len);
    fclose(mapfd);
}

void set_uid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/uid_map", pid);
    set_map(file, inside_id, outside_id, len);
}

void set_gid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/gid_map", pid);
    set_map(file, inside_id, outside_id, len);
}

int main(){
	...
	set_uid_map(container_pid, 0, uid, 1);
	set_gid_map(container_pid, 0, gid, 1);
	...
}
```

#### 容器进程

```c
char* const container_args[] = {
    "/bin/bash",
    NULL
};

int container_main(void* arg){
    sethostname("container",10);  //设置hostname
    mount("proc", "/proc", "proc", 0, NULL); //挂载proc文件系统
    execv(container_args[0], container_args);
    return 1;
}

```

#### 运行测试

```
ubuntu@VM-16-3-ubuntu:~/project/namespace$ ./container 
root@container:~/project/namespace# ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.1   6316  4568 pts/10   S    22:01   0:00 /bin/bash
root           7  0.0  0.0   7128  3172 pts/10   R+   22:01   0:00 ps -aux
```

以`ubuntu@VM-16-3-ubuntu`启动container程序，进入容器后为`root@container`(User namespace & UTS namespace)。并且/bin/bash的pid为1（PID namespace），且只有两个进程（Mount namespace）。

### 三、内核中namespace的创建

Linux namespace主要是针对进程间资源的隔离，所以在`task_struct`结构体中有对namespace的描述

```c
struct task_struct {
    /* Namespaces: */
	struct nsproxy			*nsproxy;
}
```

可以看到，在`task_struct`结构体中，`nsproxy`域存放了指向`struct nsproxy`的指针

```c
struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};
```

那么这个`nsproxy`是如何建立的呢？

在执行`clone`系统调用时（基于kernel v5.13)：

```c
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 unsigned long, tls)

{
	struct kernel_clone_args args = {
		.flags		= (lower_32_bits(clone_flags) & ~CSIGNAL),
		.pidfd		= parent_tidptr,
		.child_tid	= child_tidptr,
		.parent_tid	= parent_tidptr,
		.exit_signal	= (lower_32_bits(clone_flags) & CSIGNAL),
		.stack		= newsp,
		.tls		= tls,
	};

	return kernel_clone(&args);
}
```

```c
pid_t kernel_clone(struct kernel_clone_args *args)
{
    ...
    p = copy_process(NULL, trace, NUMA_NO_NODE, args);
    ...
}
```

```c
static __latent_entropy struct task_struct *copy_process(
					struct pid *pid,
					int trace,
					int node,
					struct kernel_clone_args *args)
{
    p = dup_task_struct(current, node);
    ...
    retval = copy_namespaces(clone_flags, p);
}
```

`copy_process`函数主要完成进程数据结构，各种资源的初始化。初始化方式可以重新分配，也可以共享父进程资源，主要根据传入CLONE参数来确定。这里主要针对`copy_namespaces`继续分析。

```c
int copy_namespaces(unsigned long flags, struct task_struct *tsk)
{
	struct nsproxy *old_ns = tsk->nsproxy;
	struct user_namespace *user_ns = task_cred_xxx(tsk, user_ns);
	struct nsproxy *new_ns;

	if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			      CLONE_NEWPID | CLONE_NEWNET |
			      CLONE_NEWCGROUP | CLONE_NEWTIME)))) {
		if (likely(old_ns->time_ns_for_children == old_ns->time_ns)) {
			get_nsproxy(old_ns);
			return 0;
		}
	} else if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;
    
	if ((flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) ==
		(CLONE_NEWIPC | CLONE_SYSVSEM))
		return -EINVAL;

	new_ns = create_new_namespaces(flags, tsk, user_ns, tsk->fs);
	if (IS_ERR(new_ns))
		return  PTR_ERR(new_ns);

	timens_on_fork(new_ns, tsk);

	tsk->nsproxy = new_ns;
	return 0;
}
```

`copy_namespace`主要基于`tsk->nsproxy`中“旧的” namespace 创建“新的” namespace，核心函数在于 `create_new_namespace`。

```c
static struct nsproxy *create_new_namespaces(unsigned long flags,
	struct task_struct *tsk, struct user_namespace *user_ns,
	struct fs_struct *new_fs)
{
	struct nsproxy *new_nsp;
	int err;

	new_nsp = create_nsproxy();
	if (!new_nsp)
		return ERR_PTR(-ENOMEM);

	new_nsp->mnt_ns = copy_mnt_ns(flags, tsk->nsproxy->mnt_ns, user_ns, new_fs);
	if (IS_ERR(new_nsp->mnt_ns)) {
		err = PTR_ERR(new_nsp->mnt_ns);
		goto out_ns;
	}

	new_nsp->uts_ns = copy_utsname(flags, user_ns, tsk->nsproxy->uts_ns);
	if (IS_ERR(new_nsp->uts_ns)) {
		err = PTR_ERR(new_nsp->uts_ns);
		goto out_uts;
	}

	new_nsp->ipc_ns = copy_ipcs(flags, user_ns, tsk->nsproxy->ipc_ns);
	if (IS_ERR(new_nsp->ipc_ns)) {
		err = PTR_ERR(new_nsp->ipc_ns);
		goto out_ipc;
	}

	new_nsp->pid_ns_for_children =
		copy_pid_ns(flags, user_ns, tsk->nsproxy->pid_ns_for_children);
	if (IS_ERR(new_nsp->pid_ns_for_children)) {
		err = PTR_ERR(new_nsp->pid_ns_for_children);
		goto out_pid;
	}

	new_nsp->cgroup_ns = copy_cgroup_ns(flags, user_ns,
					    tsk->nsproxy->cgroup_ns);
	if (IS_ERR(new_nsp->cgroup_ns)) {
		err = PTR_ERR(new_nsp->cgroup_ns);
		goto out_cgroup;
	}

	new_nsp->net_ns = copy_net_ns(flags, user_ns, tsk->nsproxy->net_ns);
	if (IS_ERR(new_nsp->net_ns)) {
		err = PTR_ERR(new_nsp->net_ns);
		goto out_net;
	}

	new_nsp->time_ns_for_children = copy_time_ns(flags, user_ns,
					tsk->nsproxy->time_ns_for_children);
	if (IS_ERR(new_nsp->time_ns_for_children)) {
		err = PTR_ERR(new_nsp->time_ns_for_children);
		goto out_time;
	}
	new_nsp->time_ns = get_time_ns(tsk->nsproxy->time_ns);

	return new_nsp;

out_time:
	put_net(new_nsp->net_ns);
out_net:
	put_cgroup_ns(new_nsp->cgroup_ns);
out_cgroup:
	if (new_nsp->pid_ns_for_children)
		put_pid_ns(new_nsp->pid_ns_for_children);
out_pid:
	if (new_nsp->ipc_ns)
		put_ipc_ns(new_nsp->ipc_ns);
out_ipc:
	if (new_nsp->uts_ns)
		put_uts_ns(new_nsp->uts_ns);
out_uts:
	if (new_nsp->mnt_ns)
		put_mnt_ns(new_nsp->mnt_ns);
out_ns:
	kmem_cache_free(nsproxy_cachep, new_nsp);
	return ERR_PTR(err);
}
```

在`create_new_namespaces`中，首先调用了`create_nsproxy`在内核中创建了一个`nsproxy`结构体，并分别调用`copy_mnt_ns`、`copy_utsname`、`copy_ipcs`、`copy_pid_ns`、`copy_cgroup_ns`、`copy_net_ns`、`copy_time_ns`等函数完成对应的namespace的创建。



参考文献：

https://lwn.net/Articles/531114/

https://coolshell.cn/articles/17029.html

https://www.cnblogs.com/bakari/p/8560437.html

https://www.cnblogs.com/bakari/p/8823642.html
