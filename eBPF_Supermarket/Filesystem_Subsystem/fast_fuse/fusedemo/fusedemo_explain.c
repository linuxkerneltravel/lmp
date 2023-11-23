//fusedemo.c
#define FUSE_USE_VERSION 31

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#ifdef linux
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif


#define TOTOL_SIZE ((uint64_t)1024*1024*1024*2)   // totol size of fsdemo
#define BANK_SIZE (1024*1024*4)					
#define BANK_NUM (TOTOL_SIZE/BANK_SIZE)
#define CHUNK_SIZE (1024*16)
#define CHUNK_NUM (TOTOL_SIZE/CHUNK_SIZE)

#define FILE_NAME_LEN 1024

struct context{
	int chunk_index;
	size_t size;
	struct context * next;
};

struct inode{ 
	char filename[FILE_NAME_LEN];
	size_t size;
	time_t timeLastModified;
	char isDirectories;
	
	struct{
		struct context * context;
	};
	struct {
		struct inode * son;
		struct inode * bro;
	};
	
};

struct attr {
	int size;
	time_t timeLastModified;
	char isDirectories;
};

struct inode_list{
	struct inode_list * next;
	char isDirectories;
	char filename[FILE_NAME_LEN];
};
static struct fuse_operations dhmp_fs_oper = {
	.init       	= dhmp_init,
	.getattr	= dhmp_fs_getattr,
	.access		= dhmp_fs_access,
	.readdir	= dhmp_fs_readdir,
	.mknod		= dhmp_fs_mknod,
	.mkdir		= dhmp_fs_mkdir,
	.unlink		= dhmp_fs_unlink,
	.rmdir		= dhmp_fs_rmdir,
	.rename		= dhmp_fs_rename,
	.chmod		= dhmp_fs_chmod,
	.chown		= dhmp_fs_chown,
	.truncate	= dhmp_fs_truncate,
	.open		= dhmp_fs_open,

	.read		= dhmp_fs_read,
	.write		= dhmp_fs_write,
	.statfs		= dhmp_fs_statfs,
};
int main(int argc, char *argv[])
{
	dhmp_local_buf = malloc(BANK_SIZE+1);
	#ifdef DEBUG_ON
		fp = fopen(DEBUG_FILE, "ab+");
	#endif
	int ret = fuse_main(argc, argv, &dhmp_fs_oper, NULL);
	return ret;
}
