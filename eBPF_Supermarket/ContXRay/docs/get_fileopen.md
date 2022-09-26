#### 获取文件打开信息

##### 获取文件系统名称

open系统调用的处理函数为`do_sys_open`

```c
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_how how = build_open_how(flags, mode);
	return do_sys_openat2(dfd, filename, &how);
}
```

`do_sys_open`->`do_sys_openat2`

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

`do_sys_open`->`do_sys_openat2`->`do_filp_open`

```c
struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	set_nameidata(&nd, dfd, pathname);
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}
```

在`do_filp_open`内，完成了对`file`结构体的创建和初始化，并通过`path_openat`分析路径名，根据路径名逐个解析成dentry，并且通过dentry找到inode。所以在`do_filp_open`返回的`file`结构体中，是可以找到我们想要的数据的。

`struct file`

```c
struct file {
	union {
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
	struct inode		*f_inode;
    ...
}
```

`struct file`->`struct inode`

```c
struct inode {
    umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;

#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif

	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
    ...
}
```

`struct file`->`struct inode`->`struct super_block`

```c
struct super_block {
	struct list_head	s_list;		/* Keep this first */
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	unsigned char		s_blocksize_bits;
	unsigned long		s_blocksize;
	loff_t			s_maxbytes;	/* Max file size */
	struct file_system_type	*s_type;
    ...
}
```

`struct file`->`struct inode`->`struct super_block`->`struct file_system_type`

```c
struct file_system_type {
	const char *name;
	int fs_flags;
    ...
}
```

`file_system_type`的`name`字段即为我们要找的文件系统名称

BCC BPF实现：

```c
struct file * fi = (struct file *)PT_REGS_RC(ctx);
bpf_probe_read_kernel_str(info.fsname,FSNAME_LEN,fi->f_inode->i_sb->s_type->name);
```

##### 获取打开文件的完整路径

在`file`结构体中，`f_path`字段为`struct path`结构：

```c
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
}
```

`struct path`->`struct dentry`

```c
struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_spinlock_t d_seq;	/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
    ...
}
```

`struct path`->`struct dentry`->`struct qstr`

```c
struct qstr {
	union {
		struct {
			HASH_LEN_DECLARE;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};
```

`dentry`结构将其名称保存在了`qstr`结构中，最终在这里拿到了打开的文件名称。

BCC BPF实现：

```c
struct file * fi = (struct file *)PT_REGS_RC(ctx);
bpf_probe_read_kernel_str(name,FILENAME_LEN,fi->f_path.dentry->d_name.name);
```

但是这里拿到的文件名不是完整的路径，比如只是`/root/abc.txt`中的`abc.txt`，想要拿到完整的路径，还要遍历'dentry'中的`d_parent`字段

因为BPF的限制，只能写有限循环（原理是在编译器将循环展开了，其实不是真的循环），所以限制最大遍历64层

```c
static int get_full_filename(struct dentry *den,char * filename){
    int i;
    char p_name[FILENAME_LEN],tmp[FILENAME_LEN];
    struct dentry *cur_den = den;
    get_dentry_name(cur_den,filename);
    #pragma clang loop unroll(full)
    for(i=0;i<64;i++){
        if(cur_den->d_parent == 0)
            break;
        cur_den = cur_den->d_parent;
        get_dentry_name(cur_den,p_name);
        strcat_64(p_name,filename,tmp);
        bpf_probe_read_kernel_str(filename,FILENAME_LEN,tmp);
    }
    return i;
}
```

这里将获得`dentry`的文件名称封装成了函数`get_dentry_name`

```c
static void get_dentry_name(struct dentry *den,char * name){
    bpf_probe_read_kernel_str(name,FILENAME_LEN,den->d_name.name);
    add_head_slash(name); //加上路径前的`/`符号
}
```

编写了一个合并字符串的`strcat_64`，以及计算字符串长度的`strlen_64`

```c
static int strlen_64(char *str){
    int i;
    #pragma clang loop unroll(full)
    for(i=0;i<FILENAME_LEN;i++){
        if(str[i] == 0)
            break;
    }
    return i;
}

static int strcat_64(char *s1,char *s2,char *result){ //return s1+s2
    int i;
    i = strlen_64(s1);
    if(i < 1)
        return i;
    bpf_probe_read_kernel_str(result,FILENAME_LEN,s1);
    char * _result = &result[i];
    bpf_probe_read_kernel_str(_result,FILENAME_LEN-i,s2);
    return i;
}
```

加上路径前的`/`符号

```c
static int add_head_slash(char * str){
    char tmp[FILENAME_LEN];
    bpf_probe_read_kernel_str(tmp,FILENAME_LEN,str);
    char * _str = &str[1];
    bpf_probe_read_kernel_str(_str,FILENAME_LEN-1,tmp);
    str[0] = '/';
    return 1;
}
```

这样就可以获得完整的路径了。