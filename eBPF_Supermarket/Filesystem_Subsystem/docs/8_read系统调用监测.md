read.py
===

read的检测原理和write基本一样，这里只给出简析，详可参考：  
[write系统调用详解](/docs/2_write系统调用详解.md)

### 相关调用
检测方法可见：  
[监测文件系统的传统工具与BPF工具](/docs/1_监测文件系统的传统工具与BPF工具.md)
```sh
            __x64_sys_read
               ksys_read
                  __fdget_pos
                     __fget_light
                  vfs_read
                     rw_verify_area
                        security_file_permission
                           apparmor_file_permission
                              aa_file_perm
                                 rcu_read_unlock_strict
```

### 相关源码
#### ksys_read
/fs/read_write.c
```c
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}
```

#### vfs_read
/fs/read_write.c
```c
ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = rw_verify_area(READ, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_access(file);
		add_rchar(current, ret);
	}
	inc_syscr(current);
	return ret;
}
```

### BPF挂载
```py
b.attach_kprobe(event="vfs_read", fn_name="entry_vfs_read")
b.attach_kprobe(event="ksys_read", fn_name="entry_ksys_read")
b.attach_kretprobe(event="vfs_read",fn_name="exit_vfs_read")
```

### 运行结果
不添加参数实时输出正在调用read方法的详细信息：
```sh
# ./read.py
Pid:  12784
Print file read info
'-c' to show TOP10 info every 1s ordered by counts.
---------------------------------------------------
5113949464966   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=680  
5113949498955   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=1    
5113949518588   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=679  
5113949587590   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=2    
5113949605121   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=668  
5113949652195   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=4    
5113950277378   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=672  
5113950300653   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=667  
5113950319255   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=659  
5113950430993   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=4    
5113950455051   pid=3686    comm=node    pr=120   user=root  fd=34   fs=sockfs   ret=670  
```

使用参数**c**在固定时间间隔输出调用最多的进程信息：
```sh
# ./read.py -c
Pid:  12882
Print file read info
'-c' to show TOP10 info every 1s ordered by counts.
---------------------------------------------------
TIME:10:51:02  
NO.1   2001pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=2    
NO.2   1268pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=1    
NO.3   595 pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=4    
NO.4   589 pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=18   
NO.5   557 pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=11   
NO.6   220 pid=12921    comm=ps       pr=120    user=root   fd=6     fs=proc     ret=0    
NO.7   128 pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=24   
NO.8   118 pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=23   
NO.9   95  pid=4640     comm=top      pr=120    user=root   fd=9     fs=proc     ret=14   
NO.10  90  pid=3686     comm=node     pr=120    user=root   fd=34    fs=sockfs   ret=15 
```