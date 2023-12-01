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

void * bank[BANK_NUM];
char * dhmp_local_buf;
struct inode *root;

FILE * fp;
char msg[1024];
char msg_tmp[1024];

//#define DEBUG_ON
#ifdef DEBUG_ON
	#define DEBUG_FILE "/fuse_result"
	#define DEBUG(x) {sprintf(msg," %s ",x); fwrite(msg, strlen(msg), 1, fp);	fflush(fp);}
	#define DEBUG_INT(x) {sprintf(msg_tmp," %d\t",(int)x);DEBUG(msg_tmp);}
	#define DEBUG_END() {sprintf(msg,"\n"); fwrite(msg, strlen(msg), 1, fp);	fflush(fp);}
	#define DEBUG_P(x)  {sprintf(msg_tmp," %x\t",x);DEBUG(msg_tmp);}
#else
	#define DEBUG(x) {}
	#define DEBUG_INT(x) {}
	#define DEBUG_END() {}
	#define DEBUG_P(x) {}
#endif
char bitmap[CHUNK_NUM];


static int dhmp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    int init_bank_i ;
	//定义一个整型变量，用来循环计数
    for(init_bank_i = 0;init_bank_i < BANK_NUM;init_bank_i++)
            bank[init_bank_i] = malloc(BANK_SIZE);	
	//利用for循环，对int_bank_i进行计数，从0开始到BANK_NUM-1
	//为bank数组中的每个元素分配内存空间，大小为BANK_SIZE字节。
	root = (struct inode*) malloc(sizeof(struct inode));
	//为root节点分配内存空间，该节点被定义为struct inode结构体类型
	root -> bro = NULL;
	//设置root节点的bro指针为NULL
	root -> son = NULL;
	//设置root节点的son指针为NULL
	root -> isDirectories = 1;
	//设置root节点为目录类型，isDirectories为1表示的是目录，为0表示文件
	root -> size = 0;
	//设置root节点的大小为0，表示这是一个空目录
	root -> timeLastModified = time(NULL);
	//设置root节点最后修改时间为当前时间
	memset(root->filename,0,FILE_NAME_LEN);
	//清空root节点的filename数组，该数组用于存储文件名，长度为FILE_NAME_LEN
	root->filename[0] = '/';
	//设置root节点的filename数组的第一个元素为'/',表示这是一个根目录
	memset(bitmap,0,sizeof(bitmap));
	//清空bitmap数组，该数组可能用于位图操作或其他用途，函数返回0，表示初始化成功。
	return 0;
}

//用于检查用户是否有权限访问某个文件或目录
static int dhmp_fs_access(const char *path, int mask)
{
	return 0;
}

//用于获取文件或目录的属性
static int dhmp_fs_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	struct attr attr;
	//定义一个名为attr的结构体变量，这个结构体可能包含文件或目录的属性信息
	int ret = 0;
	//用来记录函数执行的结果
	if(strlen(path) == 1)
	{
	//如果路径的长度等于1，那么将根目录的属性赋值给attr结构体变量
		attr.size = 0;
		//根目录大小为0，因为它是目录，大小通常为0
		attr.isDirectories = root->isDirectories;
		//根目录的类型，1是目录，0表示文件
		attr.timeLastModified = root->timeLastModified;
		//根目录最后修改的时间
	}
	else 
	//如果路径长度大于1，则调用函数dhmpGetAttr来获取文件或目录的属性
		ret = dhmpGetAttr(path,&attr);
	if(ret < 0)
	//如果dhmpGetAttr函数的返回值小于0，那么表示获取属性失败，返回-2则表示异常退出
		return -2;
	if(attr.isDirectories == 1)
	{
		//如果attr的isDirectories属性为1
		stbuf->st_mode = S_IFDIR | 0777;
		//将stbuf的mode属性设置为S_IFDIR（表示是一个目录）,并且权限设置为0777
		stbuf->st_size = 0;
		//同时将size属性设置为0，因为目录的大小通常为0
	}
	else
	// 如果attr的isDirectories属性为0，
	{
		stbuf->st_size = attr.size;
		//同时将size属性设置为attr的size属性，因为普通文件的大小就是其内容的大小
		stbuf->st_mode = S_IFREG | 0777;
		//将stbuf的mode属性设置为S_IFREG,并且权限同样设置为0777
	}

    	stbuf->st_nlink = 1;            /* Count of links, set default one link. */
		//stbuf的nlink属性表示链接数，这里设置为1，表示默认有一个链接
    	stbuf->st_uid = 0;              /* User ID, set default 0. */
		//stbuf的uid属性表示所有者的用户ID，这里设置为0，表示默认是root用户
    	stbuf->st_gid = 0;              /* Group ID, set default 0. */
		//stbuf的gid属性表示所有者的组ID，这里设置为0，表示默认是root用户组
    	stbuf->st_rdev = 0;             /* Device ID for special file, set default 0. */
    	//stbuf的rdev属性表示特殊的设备ID，这里设置为0，表示默认没有特殊设备
		stbuf->st_atime = 0;            /* Time of last access, set default 0. */
    	//stbuf的atime属性表示最后一次访问的时间，这里设置为0，表示默认没有访问记录
		stbuf->st_mtime = attr.timeLastModified; /* Time of last modification, set default 0. */
    	//stbuf的mtime属性表示最后一次修改的时间，这里设置为attr的timeLastModified，因为它是最后修改的时间
		stbuf->st_ctime = 0;            /* Time of last creation or status change, set default 0. */
		//stbuf的ctime属性表示最后一次创建或状态改变的时间，这里设置为0，表示默认没有记录
	return 0;

}

static int dhmp_fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{

	struct inode_list list,*tmp;
	//定义一个名为list的struct inode_list类型变量，和一个指向这个变量的指针tmp。inode_list可能是一个包含文件或目录信息的结构体
	uint32_t i;
	//定义一个uint32_t类型的变量i
	struct stat st;
	//定义一个struct stat类型的变量st，用于存储文件或目录的状态信息
	dhmpReadDir(path,&list);
	//调用dhmpReadDir函数读取path路径下的文件和目录列表，结果存入list
	tmp = &list;
	//将指针tmp指向list
	if(tmp->isDirectories == -1) return 0;
	//如果tmp指向的文件的isDirectories属性为-1，则返回0，表示没有读取到任何文件或目录
	for(; tmp != NULL; tmp = tmp->next)
	{
	//遍历tmp指向的所有文件和目录
		memset(&st, 0, sizeof(st));
		//将st清零，准备存储下一个文件或目录的状态信息
		st.st_mode = (tmp->isDirectories == 1) ? S_IFDIR : S_IFMT;
		//根据tmp指向的文件或目录的isDirectories属性设置st的mode属性
		//如果isDirectories为1，则mode设为S_IFDIR（表示是一个目录），否则设为S_IFMT（表示是一个普通文件）
		if (filler(buf, tmp->filename, &st, 0,0))
		// 调用filler函数，将tmp指向的文件或目录的名称、状态信息和偏移量填充到buf中
			break;
	}
	return 0;
}



static int dhmp_fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	//用于保存函数的执行结果
	res = dhmpMknod(path);
	//调用dhmpMknod函数，使用path路径创建新的节点
	//函数的返回值保存在变量res中
	if(res < 0)//说明创建失败
		return -1;
	else//创建节点成功，函数返回0
		return 0;
}
static int dhmp_fs_mkdir(const char *path, mode_t mode)
{
	int res = dhmpCreateDirectory( path);
	if(res < 0)
		return -1;
	else
		return 0;
}

//用于在文件系统中删除一个空目录
static int dhmp_fs_rmdir(const char *path)
{
	int res = dhmpDelete(path);
	//调用dhmpDelete函数，使用path路径删除一个空目录
	if(res < 0)//说明操作失败
		return -2;
	else //操作成功
		return 0;
}

//用于删除一个文件或目录
static int dhmp_fs_unlink(const char *path)
{
	int res = dhmpDelete(path);
	//调用dhmpDelete函数，使用path路径删除指定的文件或目录
	if(res < 0)//说明操作失败
		return -2;
	else//说明操作成功
		return 0;
}

//重命名文件
static int dhmp_fs_rename(const char *from, const char *to, unsigned int flags)
{
	char filename[FILE_NAME_LEN],dirname[FILE_NAME_LEN],toname[FILE_NAME_LEN];
	//定义一个字符数组，用于存储文件名（filename），目录名（dirname）和目标文件名（toname）
	int len = strlen(from);
	//获取源文件路径的长度
	strcpy(filename,from);
	//将源文件路径复制到filename数组中
	filename[len] = '/'; filename[len+1] = 0;
	//在源文件路径末尾添加一个斜杠，以分离出目录名
	struct inode* head = get_father_inode(filename);
	//获取源文件所在的父目录的inode
	if(head == NULL) return -17;
	//如果获取inode失败，返回错误代码-17
	deal(to,dirname,toname);
	// 处理目标文件路径，将目录名和目标文件名分离出来
	DEBUG(head->filename);
	//打印调试信息，显示源文件名和目标文件名
	DEBUG(toname);
	DEBUG_END();
	//打印调试信息的结束标记
	strcpy(head->filename, toname);
	//将源文件的文件名替换为目标文件名
	return 0;
}

//改变已存在文件的权限
static int dhmp_fs_chmod(const char *path, mode_t mode,
		     struct fuse_file_info *fi)
{
	return 0;
}

//用于改变文件或目录的所有者和组
static int dhmp_fs_chown(const char *path, uid_t uid, gid_t gid,
		     struct fuse_file_info *fi)
{
	return 0;
}

//用于截断文件到指定的长度
static int dhmp_fs_truncate(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	return 0;
}

//打开文件
static int dhmp_fs_open(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

//读取文件
static int dhmp_fs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	char *bbuf = malloc(size);
	//动态分配内存，创建一个char类型的指针bbuf，其大小为size
	char filename[FILE_NAME_LEN];
	//用于存储文件名
	int len = strlen(path);
	//获取path的长度
	strcpy(filename,path);
	//将path复制到filename
	filename[len] = '/'; filename[len+1] = 0;
	//在filename末尾添加一个斜杠'/'，并添加一个字符串结束符'\0'
	struct inode* head = get_father_inode(filename);
	// 获取filename对应的inode
	if(head == NULL || head->isDirectories == 1) return -1;
	//如果inode为空或者是一个目录，返回错误代码-1
	struct context * cnt = head->context;
	//获取inode关联的上下文结构体cnt
	if(cnt == NULL) return 0;//如果cnt为空，返回0
	off_t read_offset = offset;
	//设置读取的偏移量为offset
	int i = read_offset / CHUNK_SIZE;
	//计算出偏移量在CHUNK_SIZE下的余数i
	while(i > 0)
	{
		if(cnt == NULL || cnt -> size  != CHUNK_SIZE){ DEBUG("dhmp_fs_read error");return 0;}
		//如果cnt为空或者cnt的大小不等于CHUNK_SIZE，打印错误信息并返回0
		cnt = cnt->next;
		i--;
	}
	read_offset = read_offset % CHUNK_SIZE;
	//将偏移量对CHUNK_SIZE取余，并将结果赋值给read_offset
	size_t read_size = 0,un_read_size = size;
	//将用于跟踪已读取和未读取的字节数
	while(un_read_size > 0)
	{
		if(cnt == NULL) {DEBUG("dhmp_fs_read eror");break;}
		//如果cnt为空，打印错误信息并退出循环
		if(un_read_size >= cnt->size - read_offset){
			// 如果未读取的字节数大于等于当前chunk大小减去偏移量read_offset，进行一次完整的读取
			dhmp_fs_read_from_bank( cnt->chunk_index, bbuf + read_size, (cnt->size - read_offset), read_offset);
			//从磁盘上读取数据到bbuf中。参数分别是当前chunk的索引、bbuf的偏移量、要读取的字节数和偏移量
			read_size += cnt->size - read_offset;
			//更新已读取字节数，并从未读取字节数中减去已读取的字节数
			un_read_size = un_read_size - (cnt->size - read_offset);
			read_offset = 0;
			//将偏移量重置为0
		}
		else
		//如果未读取的字节数小于当前chunk的大小减去偏移量，则分次读取
		{
			dhmp_fs_read_from_bank( cnt->chunk_index, bbuf + read_size , un_read_size, read_offset);
			//从磁盘上读取数据到bbuf中
			read_size += un_read_size;
			un_read_size = 0;
		}
		cnt = cnt->next;
	}
	bbuf[read_size] = 0;
	//在bbuf后添加一个结束符，保证读取的内容为字符串形式
	memcpy(buf,bbuf,read_size);
	//将bbuf中的内容复制到buf中
	free(bbuf);
	//返回实际读取的字节数
	return read_size;
}
//用于向打开的文件中写入数据
static int dhmp_fs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;
	//用于存储函数返回的结果
	char filename[FILE_NAME_LEN];
	//用于存储文件名
	int len = strlen(path);
	strcpy(filename,path);
	filename[len] = '/'; filename[len+1] = 0;
	//在路径末尾添加一个斜杠'/', 用于分隔目录和文件名
	struct inode* head = get_father_inode(filename);
	if(head == NULL || head->isDirectories == 1) return -1;
	//获取包含该文件的父目录的inode。如果获取失败或该文件是目录，则返回错误代码-1
	struct context * cnt = head->context;
	//获取文件的上下文信息。如果获取失败，则返回0
	if(cnt == NULL)
	{
		head->context = malloc(sizeof(struct context));
		cnt = head->context;
		cnt->size = 0;
		//如果文件的上下文信息为空，为该文件创建一个新的上下文信息，并将其分配给inode的上下文字段
		cnt->chunk_index = getFreeChunk();
		//为新创建的上下文信息分配一个空闲的chunk
		cnt->next = NULL;
		//将新创建的上下文信息的下一个字段设置为NULL
	}
	off_t write_offset = offset;
	int i = write_offset / CHUNK_SIZE;
	//计算写入文件的偏移量在chunk中的位置
	write_offset = write_offset % CHUNK_SIZE;
	//计算在chunk中的具体偏移量
	while(i > 0)
	{
		if(cnt == NULL) return 0;
		if(cnt -> size  != CHUNK_SIZE) return 0;
		i--;
		if(i == 0 && write_offset == 0 && cnt->next == NULL)
		{
			cnt->next = malloc(sizeof(struct context));
			//如果当前遍历到最后一个chunk，且该chunk的偏移量为0，且该chunk的下一个字段为空，则说明该文件还未写入新的数据块，需要新建一个数据块
			cnt->next->size = 0;
			cnt->next->chunk_index = getFreeChunk();
			//为新创建的上下文信息分配一个空闲的chunk
			cnt->next->next = NULL;
		}
		cnt = cnt->next;
	}
	
	size_t write_size = 0,un_write_size = size;
	while(un_write_size > 0)
	//进入一个while循环，条件是un_write_size大于0，也就是还有数据要写入 
	{
		if(un_write_size >= (CHUNK_SIZE - write_offset)){
			dhmp_fs_write_to_bank(cnt->chunk_index, buf + write_size, (CHUNK_SIZE - write_offset), write_offset);
			//调用一个函数，将一块数据写入到指定的块中，这个块是由cnt->chunk_index指定的
			write_size += (CHUNK_SIZE - write_offset);
			//更新write_size，表示已经写入了一块数据  
			un_write_size = un_write_size - (CHUNK_SIZE - write_offset);
			//head->size += (CHUNK_SIZE - write_offset);
			//更新un_write_size，表示已经处理了一块数据  
			head->size = head->size - cnt->size + CHUNK_SIZE;
			//更新头结点的size，这里应该是要更新cnt->size，看起来可能有点错误，因为这样实际上是增加了头结点的size  
			write_offset = 0;
			//重置write_offset，准备下一轮循环写入下一块数据  
			cnt->size = CHUNK_SIZE;
			//设置cnt->size为CHUNK_SIZE，表示这个块已经写满了  
			if(cnt->next == NULL && un_write_size > 0)
			{
				cnt->next = malloc(sizeof(struct context));
				cnt->next->size = 0;
				cnt->next->chunk_index = getFreeChunk();
				cnt->next->next = NULL;
			}//如果当前块是最后一个块，且还有剩余的数据要写入，就新建一个块  
		}
		else
		{
			dhmp_fs_write_to_bank(cnt->chunk_index, buf + write_size , un_write_size, write_offset);
			//如果剩余的数据小于（CHUNK_SIZE - write_offset），就调用函数写入剩余的数据  
			write_size += un_write_size;
			//更新write_size，表示已经写入了一块数据  
			if(cnt->size != CHUNK_SIZE)
			{
				head->size = head->size - cnt->size;
				cnt->size = un_write_size + write_offset;
				head->size += cnt->size;
			}
			// 如果当前块的size不等于CHUNK_SIZE，就更新头结点的size并设置当前块的size为（un_write_size + write_offset）  
			un_write_size = 0;
			//将un_write_size设置为0，因为所有的数据都已经被写入了 
		}
		cnt = cnt->next;
	}
	return size;
}

//用于获取文件系统的状态信息
static int dhmp_fs_statfs(const char *path, struct statvfs *stbuf)
{
	stbuf->f_bsize = BANK_SIZE;
	//将stbuf的f_bsize成员设置为BANK_SIZE
	//f_bsize是文件系统中的块大小
	return 0;
}


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


//主函数
int main(int argc, char *argv[])
{
	dhmp_local_buf = malloc(BANK_SIZE+1);
	//动态分配了一个内存块
	#ifdef DEBUG_ON
		fp = fopen(DEBUG_FILE, "ab+");
	#endif
	int ret = fuse_main(argc, argv, &dhmp_fs_oper, NULL);
	//fuse_main,它允许用户在用户空间中实现自己的文件系统
	return ret;
}


