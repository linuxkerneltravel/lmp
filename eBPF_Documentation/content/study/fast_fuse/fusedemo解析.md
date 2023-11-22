## 一、主函数
```c
int main(int argc, char *argv[])
{
	// 分配本地缓冲区
	dhmp_local_buf = malloc(BANK_SIZE+1);
	//是否开启调试
	#ifdef DEBUG_ON
		fp = fopen(DEBUG_FILE, "ab+");
	#endif
	//调用 fuse_main 函数，启动 FUSE 文件系统
	int ret = fuse_main(argc, argv, &dhmp_fs_oper, NULL);
	return ret;
}
```
### 相关libfuse库函数
#### （1）`fuse_main`函数
该部分源码在libfuse库里定义为/include/fuse.h
```c
/**
 * The real main function
 *
 * Do not call this directly, use fuse_main()
 */
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		   size_t op_size, void *private_data);
```
参数：
- `argc` 和 `argv`：用于传递程序的命令行参数。这些参数将包含 FUSE 特定的参数，以及用户自定义的参数。

- `op`：一个指向 `struct fuse_operations` 结构体的指针，该结构体包含了用户实现的文件系统操作的函数指针。

- `op_size`：`struct fuse_operations` 结构体的大小

- `private_data`：一个指向私有数据的指针，用于传递用户特定的数据给文件系统操作函数。
## 二、 fuse_operations 结构体
该部分源码在libfuse库里定义为/include/fuse.h，自定义的文件系统操作函数，通过定义一个结构体，里面包含相应的自定义函数的指针，将其指向libfuse库相应的成员，最终告诉 FUSE 库在执行文件系统操作时应该调用哪些自定义的函数
```c
static struct fuse_operations dhmp_fs_oper = {
	.init       	= dhmp_init,		// 初始化文件系统
	.getattr	= dhmp_fs_getattr,		// 获取文件属性
	.access		= dhmp_fs_access,		// 检查文件访问权限
	.readdir	= dhmp_fs_readdir,		// 读取目录内容
	.mknod		= dhmp_fs_mknod,		// 创建节点
	.mkdir		= dhmp_fs_mkdir,		// 创建目录
	.unlink		= dhmp_fs_unlink,		// 删除文件
	.rmdir		= dhmp_fs_rmdir,		// 删除目录
	.rename		= dhmp_fs_rename,		// 重命名文件或目录
	.chmod		= dhmp_fs_chmod,		// 修改文件权限
	.chown		= dhmp_fs_chown,		// 修改文件所有者
	.truncate	= dhmp_fs_truncate,		// 截断文件
	.open		= dhmp_fs_open,			// 打开文件
	.read		= dhmp_fs_read,			// 读取文件内容
	.write		= dhmp_fs_write,		// 写入文件内容
	.statfs		= dhmp_fs_statfs,		// 获取文件系统统计信息
};
```


## 三、`dhmp_init`函数
该函数的功能是在文件系统启动时进行初始化
```c
static int dhmp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	// 初始化各个内存池（bank）
    int init_bank_i ;
    for(init_bank_i = 0;init_bank_i < BANK_NUM;init_bank_i++)
            bank[init_bank_i] = malloc(BANK_SIZE);	
    
    // 初始化文件系统的根目录（root）
	root = (struct inode*) malloc(sizeof(struct inode));
	root -> bro = NULL;
	root -> son = NULL;
	root -> isDirectories = 1;		//表示为目录文件
	root -> size = 0;
	root -> timeLastModified = time(NULL);
	memset(root->filename,0,FILE_NAME_LEN);
	root->filename[0] = '/';

	// 初始化位图（bitmap）
	memset(bitmap,0,sizeof(bitmap));
	return 0;	//0表示初始化成功
}
```

### 相关结构体
#### （1）`inode`结构体
该部分代码定义在fusedemo中
```c
struct inode {
    char filename[FILE_NAME_LEN];    // 文件或目录的名称
    size_t size;                     // 文件的大小（字节数）
    time_t timeLastModified;         // 最后修改时间
    char isDirectories;              // 表示是否是目录，1 表示是目录，0 表示是文件
    
    struct {
        struct context *context;     // 文件或目录的上下文信息
    };
    
    struct {
        struct inode *son;           // 指向第一个子节点（如果是目录）
        struct inode *bro;           // 指向兄弟节点
    };
};
```
#### （2）位图
该部分代码定义在fusedemo中，用位图来表示文件系统的块是否被使用，这是一种高效的方法
```c
#define CHUNK_SIZE (1024*16)
char bitmap[CHUNK_NUM];
```


#### （3）`bank`内存池
该部分代码定义在fusedemo中，将内存池用于存储文件系统的缓冲区或其他需要频繁分配和释放内存的数据结构。通过预分配内存池，避免在运行时频繁调用 malloc 和 free，从而提高程序的性能
```c
#define TOTOL_SIZE ((uint64_t)1024*1024*1024*2)		//文件系统的总大小
#define BANK_SIZE (1024*1024*4)						//内存块的大小为 4MB		
#define BANK_NUM (TOTOL_SIZE/BANK_SIZE)				//内存块数量
void * bank[BANK_NUM];								//指向大小为 BANK_SIZE 字节的内存块的指针
```

## 四、`dhmp_fs_getattr`函数
该函数用于获取文件或目录的属性信息
```c
/**
 * 获取文件或目录的属性信息
 *
 * path 文件或目录的路径
 * stbuf 用于存储属性信息的结构体指针（struct stat）
 * fi 文件信息结构体指针（fuse_file_info），可为空
 * return 返回操作是否成功，成功返回0，失败返回负值
 */
static int dhmp_fs_getattr(const char *path, struct stat *stbuf,
                            struct fuse_file_info *fi) {
    // 用于存储获取到的文件或目录属性信息的结构体
    struct attr attr;
    
    // 用于保存操作的返回值
    int ret = 0;

    // 如果路径长度为1，说明是根目录
    if (strlen(path) == 1) {
        attr.size = 0;
        attr.isDirectories = root->isDirectories;
        attr.timeLastModified = root->timeLastModified;
    } else {
        // 否则，调用自定义的 dhmpGetAttr 函数获取属性信息
        ret = dhmpGetAttr(path, &attr);
    }

    // 如果获取属性信息失败，则返回错误码
    if (ret < 0) {
        return -2;
    }

    // 根据属性信息设置 struct stat 结构体
    if (attr.isDirectories == 1) {
        // 如果是目录，设置目录的权限和大小
        stbuf->st_mode = S_IFDIR | 0777;
        stbuf->st_size = 0;
    } else {
        // 如果是文件，设置文件的大小和权限
        stbuf->st_size = attr.size;
        stbuf->st_mode = S_IFREG | 0777;
    }

    // 设置 struct stat 结构体的其他属性
    stbuf->st_nlink = 1;                // 链接数，默认为1
    stbuf->st_uid = 0;                  // 用户ID，默认为0
    stbuf->st_gid = 0;                  // 组ID，默认为0
    stbuf->st_rdev = 0;                 // 用于特殊文件的设备ID，默认为0
    stbuf->st_atime = 0;                // 上次访问时间，默认为0
    stbuf->st_mtime = attr.timeLastModified; // 上次修改时间
    stbuf->st_ctime = 0;                // 上次创建或状态修改时间，默认为0

    // 返回成功
    return 0;
}
```
