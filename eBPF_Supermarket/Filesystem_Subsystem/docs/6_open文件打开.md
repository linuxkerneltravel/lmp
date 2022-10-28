open.py
===

有BCC的opensnoopy珠玉在前，本脚本只是简单地打印了一些和open相关的信息  
### 监测点确定
`do_sys_openat2`用于追踪进程相关信息:
```py
b.attach_kprobe(event="do_sys_openat2", fn_name="entry_do_sys_openat2")
b.attach_kretprobe(event="do_sys_openat2",fn_name="exit_do_sys_openat2")
```

`do_filp_open`用于追踪文件相关信息:
```py
b.attach_kprobe(event="do_sys_openat2", fn_name="entry_do_sys_openat2")
b.attach_kretprobe(event="do_sys_openat2",fn_name="exit_do_sys_openat2")
```

### 输出
#### 时间戳
```c
u64 ts = bpf_ktime_get_ns();
```
#### 进程号
```c
u64 id = bpf_get_current_pid_tgid();
```

#### 进程名
```c
bpf_get_current_comm(&val.comm, sizeof(val.comm))
```

#### 所属用户
```c
u32 uid = bpf_get_current_uid_gid();
```

#### 进程优先级
```c
tp = (struct task_struct*)bpf_get_current_task();
val.pr = tp->prio;
```

#### 文件描述符
```c
int fd = PT_REGS_RC(ctx);
```

#### 文件标志位
```c
val.flags = how->flags;
```

#### 文件系统类型
```c
bpf_probe_read_kernel_str(fs.fstype, sizeof(fs.fstype), fp->f_inode->i_sb->s_type->name);
```

#### 文件打开路径
```c
bpf_probe_read_user_str(val.fname, sizeof(val.fname), filename);
```

### 运行结果
不添加参数实时输出正在调用open方法的详细信息：
```sh
./open.py 
Pid:  74801
Print file open info
'-c' to show TOP10 info every 1s ordered by counts.
---------------------------------------------------
60385222808059  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/memory.swap.current
60385222866407  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/memory.stat
60385223024301  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.pressure
60385223155758  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.current
60385223214908  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.min
60385223271875  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.low
60385223327880  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.swap.current
60385223384195  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.stat
60385223517237  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=cgroup2 path=/proc/meminfo     
60385251249442  pid=3159    comm=node    pr=120   user=root  fd=21   flag=00100000  fs=proc    path=/proc/74801/cmdline
60385451764150  pid=3159    comm=node    pr=120   user=root  fd=21   flag=00100000  fs=proc    path=/proc/74801/cmdline
60385472426168  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=proc    path=/proc/meminfo     
60385652291432  pid=3159    comm=node    pr=120   user=root  fd=21   flag=00100000  fs=proc    path=/proc/74801/cmdline
60385722445586  pid=430     comm=systemd-oomdpr=120   user=systemd-oomfd=7    flag=02100000  fs=proc    path=/proc/meminfo  
```

使用**c**参数在固定时间间隔输出调用最多的进程信息：
```sh
# ./open.py -c
Pid:  74886
Print file open info
'-c' to show TOP10 info every 1s ordered by counts.
---------------------------------------------------
TIME:01:57:11  
NO.1   14  pid=3159     comm=node     pr=120    user=root   fd=21    flag=00100000 fs=proc     path=/proc/74886/cmdline
NO.2   9   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=proc     path=/proc/meminfo     
NO.3   2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.min
NO.4   2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.low
NO.5   2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/memory.swap.current
NO.6   2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/proc/meminfo     
NO.7   2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.stat
NO.8   2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/memory.low
NO.9   2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/sys/fs/cgroup/user.slice/user-0.slice/user@0.service/memory.swap.current
NO.10  2   pid=430      comm=systemd-oomd pr=120    user=systemd-oom fd=7     flag=02100000 fs=cgroup2  path=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/memory.min
```

### 问题
在脚本运行过程中会检测到自身产生的PID，为性能起见将其删除：
```py
self = os.getpid()

bpf_text = """
...
	if (self == %d)
		return 0;
...
""" % self
```

### 相关源码
#### do_sys_open
/fs/open.c
```c
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_how how = build_open_how(flags, mode);
	return do_sys_openat2(dfd, filename, &how);
}
```

#### do_sys_openat2
/fs/open.c
```c
static long do_sys_openat2(int dfd, const char __user *filename,
			   struct open_how *how)
{
	struct open_flags op;
	int fd = build_open_flags(how, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(how->flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
		}
	}
	putname(tmp);
	return fd;
}
```

#### do_filp_open
/fs/namei.c
```py
struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	set_nameidata(&nd, dfd, pathname, NULL);
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}
```
#### path_openat
/fs/namei.c
```c
static struct file *path_openat(struct nameidata *nd,
			const struct open_flags *op, unsigned flags)
{
	struct file *file;
	int error;

	file = alloc_empty_file(op->open_flag, current_cred());
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(nd, flags, op, file);
	} else if (unlikely(file->f_flags & O_PATH)) {
		error = do_o_path(nd, flags, file);
	} else {
		const char *s = path_init(nd, flags);
		while (!(error = link_path_walk(s, nd)) &&
		       (s = open_last_lookups(nd, file, op)) != NULL)
			;
		if (!error)
			error = do_open(nd, file, op);
		terminate_walk(nd);
	}
	if (likely(!error)) {
		if (likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	fput(file);
	if (error == -EOPENSTALE) {
		if (flags & LOOKUP_RCU)
			error = -ECHILD;
		else
			error = -ESTALE;
	}
	return ERR_PTR(error);
}
```

#### do_open
/fs/namei.c
```c
static int do_open(struct nameidata *nd,
		   struct file *file, const struct open_flags *op)
{
	struct user_namespace *mnt_userns;
	int open_flag = op->open_flag;
	bool do_truncate;
	int acc_mode;
	int error;

	if (!(file->f_mode & (FMODE_OPENED | FMODE_CREATED))) {
		error = complete_walk(nd);
		if (error)
			return error;
	}
	if (!(file->f_mode & FMODE_CREATED))
		audit_inode(nd->name, nd->path.dentry, 0);
	mnt_userns = mnt_user_ns(nd->path.mnt);
	if (open_flag & O_CREAT) {
		if ((open_flag & O_EXCL) && !(file->f_mode & FMODE_CREATED))
			return -EEXIST;
		if (d_is_dir(nd->path.dentry))
			return -EISDIR;
		error = may_create_in_sticky(mnt_userns, nd,
					     d_backing_inode(nd->path.dentry));
		if (unlikely(error))
			return error;
	}
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
		return -ENOTDIR;

	do_truncate = false;
	acc_mode = op->acc_mode;
	if (file->f_mode & FMODE_CREATED) {
		/* Don't check for write permission, don't truncate */
		open_flag &= ~O_TRUNC;
		acc_mode = 0;
	} else if (d_is_reg(nd->path.dentry) && open_flag & O_TRUNC) {
		error = mnt_want_write(nd->path.mnt);
		if (error)
			return error;
		do_truncate = true;
	}
	error = may_open(mnt_userns, &nd->path, acc_mode, open_flag);
	if (!error && !(file->f_mode & FMODE_OPENED))
		error = vfs_open(&nd->path, file);
	if (!error)
		error = ima_file_check(file, op->acc_mode);
	if (!error && do_truncate)
		error = handle_truncate(mnt_userns, file);
	if (unlikely(error > 0)) {
		WARN_ON(1);
		error = -EINVAL;
	}
	if (do_truncate)
		mnt_drop_write(nd->path.mnt);
	return error;
}
```
