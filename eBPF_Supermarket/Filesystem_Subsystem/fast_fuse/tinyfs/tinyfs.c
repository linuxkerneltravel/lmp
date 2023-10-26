// tinyfs.c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <uapi/linux/time.h>

#include "tinyfs.h"

struct file_blk block[MAX_FILES+1];
int curr_count = 0; // 全局变量

// 获得一个尚未使用的文件块，保存新创建的文件或者目录
//该函数用于查找block数组中第一个busy属性为0的元素，并返回该元素的下标
static int get_block(void)
{	
	int i;

	// 就是一个遍历，但实现快速。
	for (i = 2; i < MAX_FILES; i++) {//数组下标从2开始遍历是因为该程序将下标0和下标1分别预留给了根目录和当前目录
        	if (!block[i].busy) {	//如果当前元素的busy属性为0，则将其busy属性置为1，表示已被占用，并返回该元素的下标
            	block[i].busy = 1;
            	return i;
        	}
    	}
    	return -1;					//如果数组中所有元素的busy属性均为1，则返回-1，表示数组已满，无法再分配新的元素
}

static struct inode_operations tinyfs_inode_ops;
// 读取目录的实现
static int tinyfs_iterate(struct file *filp, struct dir_context *dirent)
{
    	loff_t pos;
	filldir_t filldir;
    	struct file_blk *blk;
    	struct dir_entry *entry;
    	int i;

    	pos = filp->f_pos;
	filldir = dirent->actor;
    	if (pos)
        	return 0;

    	blk = (struct file_blk *)filp->f_inode->i_private;

    	if (!S_ISDIR(blk->mode)) {
        	return -ENOTDIR;
    	}

    	// 循环获取一个目录的所有文件的文件名
    	entry = (struct dir_entry *)&blk->data[0];
    	for (i = 0; i < blk->dir_children; i++) {
        	(*filldir)(dirent, entry[i].filename, MAXLEN, pos, entry[i].idx, DT_UNKNOWN);
        	filp->f_pos += sizeof(struct dir_entry);
        	pos += sizeof(struct dir_entry);
    	}

    	return 0;
}

// read实现
ssize_t tinyfs_read(struct file * filp, char __user * buf, size_t len, loff_t *ppos)
{	//文件结构体指针 filp，用户缓冲区 buf，要读取的字节数 len，以及文件偏移量 ppos
    	struct file_blk *blk;
    	char *buffer;

    	blk = (struct file_blk *)filp->f_path.dentry->d_inode->i_private;
    	if (*ppos >= blk->file_size)			//检查文件偏移量是否超出文件大小
        	return 0;

    	buffer = (char *)&blk->data[0];			//将 blk 中的数据缓冲区的指针存储在 buffer 变量中
    	len = min((size_t) blk->file_size, len);//将 len 和文件大小中的较小值存储在 len 变量中

    	if (copy_to_user(buf, buffer, len)) {	// copy_to_user 函数:将文件数据从内核空间复制到用户空间缓冲区 buf 中
        	return -EFAULT;
    	}
    	*ppos += len;							//更新文件偏移量 ppos

    	return len;								//返回读取的字节数 len
}

// write实现
ssize_t tinyfs_write(struct file * filp, const char __user * buf, size_t len, loff_t * ppos)
{
    	struct file_blk *blk;		// 文件块结构体指针
    	char *buffer;				// 缓冲区指针

    	blk = filp->f_path.dentry->d_inode->i_private;	 // 获取文件的私有数据，即文件块结构体指针

    	buffer = (char *)&blk->data[0];		// 将文件块结构体中的数据指针赋值给缓冲区指针
    	buffer += *ppos;					// 将缓冲区指针移动到偏移量位置

    	if (copy_from_user(buffer, buf, len)) {	// 将用户空间的数据拷贝到内核缓冲区
        	return -EFAULT;						// 拷贝失败，返回错误码
    	}
    	*ppos += len;							// 偏移量增加
    	blk->file_size = *ppos;					// 更新文件块结构体中的文件大小

    	return len;								// 返回写入的字节数
}

const struct file_operations tinyfs_file_operations = {
    	.read = tinyfs_read,
    	.write = tinyfs_write,
};

const struct file_operations tinyfs_dir_operations = {
    	.owner = THIS_MODULE,
    	.iterate = tinyfs_iterate,
};

// 创建文件的实现
static int tinyfs_do_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    	struct inode *inode;
    	struct super_block *sb;
    	struct dir_entry *entry;
    	struct file_blk *blk, *pblk;
    	int idx;

    	sb = dir->i_sb;

    	if (curr_count >= MAX_FILES) {//检查当前目录下的文件数是否已经达到了最大值
        	return -ENOSPC;			//如果是，则返回错误码-ENOSPC，表示磁盘空间已满
    	}

    	if (!S_ISDIR(mode) && !S_ISREG(mode)) {//检查要创建的是否是文件或是目录
        	return -EINVAL;
    	}

    	inode = new_inode(sb);
    	if (!inode) {
        	return -ENOMEM;
    	}

    	inode->i_sb = sb;
    	inode->i_op = &tinyfs_inode_ops;
    	//inode->i_atime = inode->i_mtime = inode->i_ctime = time(NULL);

    	idx = get_block(); // 获取一个空闲的文件块保存新文件

    	blk = &block[idx];
    	inode->i_ino = idx;
    	blk->mode = mode;
    	curr_count ++;

    	if (S_ISDIR(mode)) {//创建目录
        	blk->dir_children = 0;
        	inode->i_fop = &tinyfs_dir_operations;
    	} else if (S_ISREG(mode)) {//创建文件
        	blk->file_size = 0;
        	inode->i_fop = &tinyfs_file_operations;
    	}

    	inode->i_private = blk;
    	pblk = (struct file_blk *)dir->i_private;
		//在当前目录的文件块中添加新的目录项，记录新文件的inode编号和文件名。
    	entry = (struct dir_entry *)&pblk->data[0];
    	entry += pblk->dir_children;
    	pblk->dir_children ++;

    	entry->idx = idx;
    	strcpy(entry->filename, dentry->d_name.name);

    	//将新的inode和dentry添加到VFS的inode链表中，这是VFS中穿针引线的关键步骤
    	inode_init_owner(inode, dir, mode); 
    	d_add(dentry, inode);
		//返回0表示创建文件或目录成功
    	return 0;
}

//创建目录
static int tinyfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    	//其中S_IFDIR是文件类型标志，表示创建的是一个目录类型的文件。mode是文件权限标志，可以通过传递不同的权限标志来设置创建的目录的权限
    	return tinyfs_do_create(dir, dentry, S_IFDIR | mode);
}

//创建文件
static int tinyfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
    	//其中mode是文件权限标志，可以通过传递不同的权限标志来设置创建的文件的权限
    	return tinyfs_do_create(dir, dentry, mode);
}

//这是一个用于获取指定inode节点的函数，它接收一个超级块和一个inode号作为参数，并返回一个指向对应inode节点的指针
static struct inode *tinyfs_iget(struct super_block *sb, int idx)
{
    	struct inode *inode;
    	struct file_blk *blk;

    	//为新的inode节点分配内存
    	inode = new_inode(sb);
    	//设置inode节点的索引号和超级块
    	inode->i_ino = idx;
    	inode->i_sb = sb;
    	//设置inode节点的操作函数
    	inode->i_op = &tinyfs_inode_ops;

    	//获取指定索引号的文件块
    	blk = &block[idx];

    	//根据文件块的类型设置inode节点的文件操作函数
    	if (S_ISDIR(blk->mode))
        	inode->i_fop = &tinyfs_dir_operations;
    	else if (S_ISREG(blk->mode))
        	inode->i_fop = &tinyfs_file_operations;

    	//inode->i_atime = inode->i_mtime = inode->i_ctime = time(NULL);
    	//设置inode节点的私有数据为文件块
    	inode->i_private = blk;

    	return inode;
}

struct dentry *tinyfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
    	struct super_block *sb = parent_inode->i_sb;
    	struct file_blk *blk;
    	struct dir_entry *entry;
    	int i;

    	blk = (struct file_blk *)parent_inode->i_private;
    	entry = (struct dir_entry *)&blk->data[0];
    	for (i = 0; i < blk->dir_children; i++) {
        	if (!strcmp(entry[i].filename, child_dentry->d_name.name)) {
            		struct inode *inode = tinyfs_iget(sb, entry[i].idx);
            		struct file_blk *inner = (struct file_blk *)inode->i_private;
            		inode_init_owner(inode, parent_inode, inner->mode);
            		d_add(child_dentry, inode);
            		return NULL;
        		}
    	}

    	return NULL;
}

int tinyfs_rmdir(struct inode *dir, struct dentry *dentry)
{
    	struct inode *inode = dentry->d_inode;
    	struct file_blk *blk = (struct file_blk *)inode->i_private;

    	blk->busy = 0;
    	return simple_rmdir(dir, dentry);
}

int tinyfs_unlink(struct inode *dir, struct dentry *dentry)
{
    	int i;
    	struct inode *inode = dentry->d_inode;
    	struct file_blk *blk = (struct file_blk *)inode->i_private;
    	struct file_blk *pblk = (struct file_blk *)dir->i_private;
    	struct dir_entry *entry;

    	// 更新其上层目录
    	entry = (struct dir_entry *)&pblk->data[0];
    	for (i = 0; i < pblk->dir_children; i++) {
        	if (!strcmp(entry[i].filename, dentry->d_name.name)) {
            		int j;
            		for (j = i; j < pblk->dir_children - 1; j++) {
                		memcpy(&entry[j], &entry[j+1], sizeof(struct dir_entry));
            		}
            		pblk->dir_children --;
            		break;
        	}
    	}

    	blk->busy = 0;
    	return simple_unlink(dir, dentry);
}

static struct inode_operations tinyfs_inode_ops = {
    	.create = tinyfs_create,
    	.lookup = tinyfs_lookup,
    	.mkdir = tinyfs_mkdir,
    	.rmdir = tinyfs_rmdir,
    	.unlink = tinyfs_unlink,
};

int tinyfs_fill_super(struct super_block *sb, void *data, int silent)
{
    	struct inode *root_inode;
    	int mode = S_IFDIR;

    	root_inode = new_inode(sb);
    	root_inode->i_ino = 1;
    	inode_init_owner(root_inode, NULL, mode);
    	root_inode->i_sb = sb;
    	root_inode->i_op = &tinyfs_inode_ops;
    	root_inode->i_fop = &tinyfs_dir_operations;
    	//root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime = (timespec64)time(NULL);

    	block[1].mode = mode;
    	block[1].dir_children = 0;
    	block[1].idx = 1;
    	block[1].busy = 1;
    	root_inode->i_private = &block[1];

    	sb->s_root = d_make_root(root_inode);
    	curr_count ++;

    	return 0;
}

static struct dentry *tinyfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
    	return mount_nodev(fs_type, flags, data, tinyfs_fill_super);
}

static void tinyfs_kill_superblock(struct super_block *sb)
{
    	kill_anon_super(sb);
}

struct file_system_type tinyfs_fs_type = {
    	.owner = THIS_MODULE,
    	.name = "tinyfs",
    	.mount = tinyfs_mount,
    	.kill_sb = tinyfs_kill_superblock,
};

static int tinyfs_init(void)
{
    	int ret;

    	memset(block, 0, sizeof(block));
    	ret = register_filesystem(&tinyfs_fs_type);
    	if (ret)
        	printk("register tinyfs failed\n");

    	return ret;
}

static void tinyfs_exit(void)
{
    	unregister_filesystem(&tinyfs_fs_type);
}

module_init(tinyfs_init);
module_exit(tinyfs_exit);

MODULE_LICENSE("GPL");
