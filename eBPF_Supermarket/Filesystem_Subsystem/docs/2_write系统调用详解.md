write.py
===

### 写到磁盘涉及到的内核函数
使用命令`trace-cmd`监控一个有写入动作的程序  
详细使用可以参考另一文档：  
[传统工具与BPF工具](./1_%E7%9B%91%E6%B5%8B%E6%96%87%E4%BB%B6%E7%B3%BB%E7%BB%9F%E7%9A%84%E4%BC%A0%E7%BB%9F%E5%B7%A5%E5%85%B7%E4%B8%8EBPF%E5%B7%A5%E5%85%B7.md)

5.4内核的函数调用如下：
```sh
             do_syscall_64
                __x64_sys_write
                   ksys_write
                      __fdget_pos
                         __fget_light
                      vfs_write
                         rw_verify_area
                            security_file_permission
                               apparmor_file_permission
                                  common_file_perm
                                     aa_file_perm
                         __sb_start_write
                            _cond_resched
                               rcu_all_qs
                         __vfs_write
                            new_sync_write
                               ext4_file_write_iter
                                  down_write_trylock
                                  ext4_write_checks
```
由监控结果可知，系统由`do_syscall_64`进入系统调用，再由函数`ksys_write`进入写功能。

5.15内核的函数调用如下：
```
             __x64_sys_write
                ksys_write
                   __fdget_pos
                      __fget_light
                   vfs_write
                      rw_verify_area
                         security_file_permission
                            apparmor_file_permission
                               aa_file_perm
                                  rcu_read_unlock_strict
                      __cond_resched
```
可以看到后来的内核版本中去掉了`__vfs_write`功能，所以直接监控`vfs_write`就行。  
后续write系统调用怎么将数据写到磁盘详见另一文档：  
[从write到磁盘](./7)

### 源码分析
#### ksys_write
寻找内核函数ksys_write：  
/fs/read_write.c
```c 
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}
```
```c
ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);    //得到要操作的文件
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);  //需要写文件的位置
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_write(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}

	return ret;
}
```

#### vfs_write
/fs/read_write.c
```c
ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;
//验证是否可以操作这个文件
	ret = rw_verify_area(WRITE, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;
	file_start_write(file);
	if (file->f_op->write)
		ret = file->f_op->write(file, buf, count, pos);
	else if (file->f_op->write_iter)
		ret = new_sync_write(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	file_end_write(file);
	return ret;
}
```

在`file->f_op->write`处调用具体文件系统的写函数，file结构体中关于文件操作的字段如下：  
/include/linux/fs.h
```c
struct file {
	union {
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
	struct inode		*f_inode;	/* cached value */
	const struct file_operations	*f_op;
...
}
```

#### file_operations
/include/linux/fs.h
```c
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *kiocb, bool spin);
...
}
```
file_operations用来存储驱动内核模块提供的对设备进行各种操作的函数的指针，此处的每个域都对应着驱动内核模块用来处理某个被请求的事务的函数的地址，也就是钩子函数，在使用自己定义的写函数的时候可以使用如下语句：
```c
struct file_operations zf_file_operations
{
    .read = zf_read,
    .write = zf_write,
};
```
自定义读写函数：
```c
ssize_t zf_read (struct file *, char __user *, size_t, loff_t *)
{

}
ssize_t zf_write (struct file *, const char __user *, size_t, loff_t *)
{
    
}
```

### BPF程序
#### 确定监测点
1. 在以前的内核版本中`vfs_write`会调用内部函数`__vfs_write`来执行写入，现在省略了这一过程，所以直接对`vfs_write`进行监控就可以，BPF语句如下：
```py
b.attach_kprobe(event="vfs_write" ,fn_name="trace_syscall_write")
```

2. 或者使用如下语句也可以：
```py
fnname_write = b.get_syscall_prefix().decode() + 'write'
b.attach_kprobe(event=fnname_write ,fn_name="trace_syscall_write")
```
以上语句表示解析write系统调用的前缀并用字符串形式解码。
- **get_syscall_prefix()**：  
  返回正在运行的内核系统调用前缀；
- **decode()**：  
  以 encoding 指定的编码格式解码字符串，默认编码为字符串编码；
  用法：str.decode(encoding='UTF-8',errors='strict')

3. 或者：
```py
b.attach_kprobe(event="__x64_sys_write" ,fn_name="trace_syscall_write")
```

为了测试以上三种监测方式是否效果相同，编写以下测试程序：  
[attach_write_test.py](../tools/attach_write_test.py)

程序定义了三种状态：
- S_VFS表示监测内核函数vfs_write；
- S_GET表示使用BPF的功能get_syscall_prefix；
- S_X86表示监测系统调用入口函数__x64_sys_write。  
之后为它们绑定各自对应的函数，在系统调用到这些函数的时候自增，最后打印对比其数目，程序运行结果是：
```sh
# ./attach_write_test.py 
TIME            VFS      X86      GET
22:27:09        78       78       78
22:27:10        56       56       56
22:27:11        47       47       47
22:27:12        45       45       45
22:27:13        73       73       73
22:27:14        59       59       59
```
就结果而言，三种方式是一模一样的。一开始分析了从write的调用到内核实现，其实BPF的功能更加地快速方便，你不需要知道内部是怎么实现的，只要知道系统调用的名称即可。这么费劲地测试以及分析了一气，只是验证了BPF程序的便捷性，不过对于内核学习而言，这样的过程还是非常有必要的。

#### BPF映射
在确定BPF映射时首先选择了`perf_event机制`，但是脚本运行时出现了**内存泄漏**和**CPU使用率高**等问题。  
详见[3_buffer_poll的问题](./3_buffer_poll%E7%9A%84%E9%97%AE%E9%A2%98.md)  
所以使用`BPF_HASH`映射:
```c
BPF_HASH(write_info, u64, struct val_t);
BPF_HASH(rettmp, u64, struct tmp_t);
BPF_HASH(fdtmp, u64, struct tmp_t);
```
### 运行结果
不添加参数实时输出正在调用write方法的详细信息：
```sh
# ./write.py 
Pid:  7108
Print file write info
'-c' to show TOP10 info every 1s ordered by counts.
---------------------------------------------------
3429152383235   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=23   
3429152387577   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=454  
3429153608089   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=1    
3429153617910   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=24   
3429153622143   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=477  
3429153626773   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=23   
3429153630947   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=434  
3429154274669   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=1    
3429154282991   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=24   
3429154287115   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=481  
3429154291677   pid=6509    comm=rg      pr=120   user=root  fd=2    fs=sockfs   ret=23   
```

使用参数**c**在固定时间间隔输出调用最多的进程信息：
```sh
# ./write.py -c
Pid:  7212
Print file write info
'-c' to show TOP10 info every 1s ordered by counts.
---------------------------------------------------
TIME:10:22:59  
NO.1   2033pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=23   
NO.2   2033pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=24   
NO.3   2029pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=1    
NO.4   1009pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=432  
NO.5   453 pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=451  
NO.6   427 pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=452  
NO.7   407 pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=475  
NO.8   407 pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=479  
NO.9   338 pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=474  
NO.10  338 pid=6509     comm=rg       pr=120    user=root   fd=2     fs=sockfs   ret=478  
```