//fusedemo.c

/*这段代码是c语言中的预处理指令，用于宏定义和条件编译。*/
#define FUSE_USE_VERSION 31
//定义了一个宏名为FUSES_USE_VERSION。赋值为31
/*通常用于在编译时设置或指定FUSE的版本为31*/

#ifdef HAVE_CONFIG_H //即根据特定的条件是否编译某段代码
#include <config.h> //这个代码通常包含了一些配置信息，比如：项目的编译选项、特性开关等。
#endif
//这段代码主要用于设置FUSE的版本为31，并在满足（config.h)文件存在或被引入时
//这样做可以使得编译过程更加灵活，能够根据不同的配置和要求，编译不同的代码

#define _GNU_SOURCE
//会开启一些特定的GNU库特性

#ifdef linux
#define _XOPEN_SOURCE 700
#endif
//所以这行代码的意思是在Linux环境下使用POSIX 2008版本的特性


#include <fuse.h>
//用于使用FUSE，可以创建自己的文件系统并将其挂载到操作系统中
#include <stdio.h>
#include <string.h>
#include <unistd.h>
//包含了一些POSIX操作系统API的函数原型，主要用于read、write
#include <fcntl.h>
//包含了一些文件控制函数，open、close、read、write等
#include <stdlib.h>
#include <sys/stat.h>
//包含了处理文件状态信息的宏和函数
#include <dirent.h>
//包含了用于读取目录的函数，opendir、readdir
#include <errno.h>
//包含了表示错误代码的宏

#ifdef __FreeBSD__
#include <sys/socket.h>
#include <sys/un.h>
#endif
//用于处理socket和UNIX域socket的操作

#include <sys/time.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
//包含了处理扩展文件属性的函数和宏

#define TOTOL_SIZE ((uint64_t)1024*1024*1024*2)   //定义了一个名为TOTAL_SIZE的宏，这里设置大小为2GB
#define BANK_SIZE (1024*1024*4)	//定义一个名为BANK_SIZE的宏，表示块大小为4MB				
#define BANK_NUM (TOTOL_SIZE/BANK_SIZE)//TOTAL/BANK_SIZE，表示块的数量
#define CHUNK_SIZE (1024*16)//表示块的大小，这里设置为16KB
#define CHUNK_NUM (TOTOL_SIZE/CHUNK_SIZE)//TOTAL/CHUNK_SIZE

//这些宏用于后续的代码中，用于内存分配、数组大小的设定、循环的次数等。

#define FILE_NAME_LEN 1024
//为了设定文件名的最大长度为1024字符

struct context{
	int chunk_index;//用于标识或索引数据块
	size_t size;//用于表示块的大小
	struct context * next;//指向同类型的指针
};

struct inode{ 
	char filename[FILE_NAME_LEN];//字符数组，用于存储文件名
	size_t size;//用于存储文件大小
	time_t timeLastModified;//用于存储文件最后修改的时间
	char isDirectories;//能用于表示这个inode是否对应一个目录
	
	struct{
		struct context * context;//用于存储一些上下文信息
	};
	struct {
		struct inode * son;
		struct inode * bro;
	};
	//用于表示这个inode可以指向它的子目录和兄弟目录
};
//这个结构体提供了一个基本的框架来存储文件或目录的元数据，但具体的实现需要在其他地方完成。

struct attr {
	int size;//用于存储文件或目录的大小
	time_t timeLastModified;//用于存储文件或目录最后修改的时间
	char isDirectories;//用于表示这个文件或目录是否是一个目录
};
//这个结构体可以用于存储文件或目录的基本属性，包括大小、最后修改时间和是否是目录。
//在文件系统或操作系统中，这样的结构体会用来管理文件和目录

struct inode_list{
	struct inode_list * next; //指向结构体的指针，用于链表
	char isDirectories;//标志此节点是否表示一个目录
	char filename[FILE_NAME_LEN];//存储文件名
};
//用于表示文件系统中的inode链表中的节点

static struct fuse_operations dhmp_fs_oper = {
	.init       	= dhmp_init,
	//用于在FUSE文件系统被挂载时进行初始化操作
	.getattr	= dhmp_fs_getattr,
	//用于获取文件或目录的属性
	.access		= dhmp_fs_access,
	//用于检查用户是否有权限访问某个文件或目录
	.readdir	= dhmp_fs_readdir,
	//用于读取目录的内容
	.mknod		= dhmp_fs_mknod,
	//用于创建特殊的文件类型（如设备节点）
	.mkdir		= dhmp_fs_mkdir,
	//用于创建目录
	.unlink		= dhmp_fs_unlink,
	//用于删除文件
	.rmdir		= dhmp_fs_rmdir,
	//用于删除目录
	.rename		= dhmp_fs_rename,
	//用于重命名文件或目录
	.chmod		= dhmp_fs_chmod,
	//用于改变文件或目录的权限
	.chown		= dhmp_fs_chown,
	//用于改变文件或目录的所有者和组
	.truncate	= dhmp_fs_truncate,
	//用于截断文件到指定的长度
	.open		= dhmp_fs_open,
	//用于打开文件
	.read		= dhmp_fs_read,
	//用于从打开的文件中读取数据
	.write		= dhmp_fs_write,
	//用于向打开的文件中写入数据
	.statfs		= dhmp_fs_statfs,
	//用于获取文件系统的状态信息
};
//定义一个FUSE操作集，用于在用户用户空间中实现文件系统
