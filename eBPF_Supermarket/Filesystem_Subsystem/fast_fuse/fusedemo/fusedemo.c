

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

int getFreeChunk()
{
	int i =0;
	for(;i < CHUNK_NUM; i++)
	{
		if(bitmap[i] == 1)continue;
		break;
	}
	if(i == CHUNK_NUM)
	DEBUG("Error:no space for free chunk");
	bitmap[i] = 1;
	DEBUG("getFreeChunk = ");
	DEBUG_INT(i);
	DEBUG_END();
	return i;
}

void dhmp_fs_read_from_bank( int chunk_index, char * buf, size_t size, off_t chunk_offset)
{
	DEBUG("dhmp_fs_read_from_bank size =");
	DEBUG_INT(size);
	DEBUG("chunk_offset=");
	DEBUG_INT(chunk_offset);

	void * tbank = (bank[chunk_index / (CHUNK_NUM/BANK_NUM)]);
	int times = chunk_index % (CHUNK_NUM/BANK_NUM);
	off_t offset = chunk_offset + times * CHUNK_SIZE;
	DEBUG("chunk ==  ");
	DEBUG_INT(chunk_index);
	DEBUG("chunkoffset=");
	DEBUG_INT(offset);
	DEBUG_INT(times);

	size_t Tsize = chunk_offset + size + times * CHUNK_SIZE;
	memcpy(dhmp_local_buf, tbank, Tsize);

	memcpy(buf, dhmp_local_buf + offset, size);
}

void dhmp_fs_write_to_bank(int chunk_index, char * buf, size_t size, off_t chunk_offset)
{
	DEBUG("dhmp_fs_write_to_bank size =");
	DEBUG_INT(size);
	DEBUG("chunk_offset=");
	DEBUG_INT(chunk_offset);

	void * tbank = (bank[chunk_index / (CHUNK_NUM/BANK_NUM)]);
	int times = chunk_index % (CHUNK_NUM/BANK_NUM);
	off_t offset = chunk_offset + times * CHUNK_SIZE;
	DEBUG("chunk = =");
	DEBUG_INT(chunk_index );
	DEBUG("chunkoffset=");
	DEBUG_INT(offset);
	DEBUG_INT(times);

	size_t Tsize = chunk_offset + size + times * CHUNK_SIZE;
	memcpy(dhmp_local_buf, tbank, offset);
	memcpy(dhmp_local_buf + offset, buf, size);
	memcpy(tbank, dhmp_local_buf, Tsize);
}

static int dhmp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    int init_bank_i ;
    for(init_bank_i = 0;init_bank_i < BANK_NUM;init_bank_i++)
            bank[init_bank_i] = malloc(BANK_SIZE);	
	root = (struct inode*) malloc(sizeof(struct inode));
	root -> bro = NULL;
	root -> son = NULL;
	root -> isDirectories = 1;
	root -> size = 0;
	root -> timeLastModified = time(NULL);
	memset(root->filename,0,FILE_NAME_LEN);
	root->filename[0] = '/';
	memset(bitmap,0,sizeof(bitmap));
	return 0;
}

static int dhmp_fs_access(const char *path, int mask)
{
	return 0;
}



/* brief: deal path to dir/file mode
 * transfaring	(/root/lhd/node)  to (/root/lhd/ node)
 * transfaring 	(/root/lhd/node/) to (/root/lhd/ node)
 * do not do anything with root(/) dir 
 * 			*/
void deal(const char *path,char * dirname,char * filename)
{
	int i =0,j=0,k = 0,m=0;
	int len = strlen(path);
	for(;i < len;i++)
	{
		dirname[i] = path[i];
		if(path[i] == '/' && path[i+1] != 0) j = i;
	}
	m = j++;
	for(;j < len;)
	{
		filename[k] = path[j];
		k++;j++;
	}
	dirname[m+1] = 0;
	if(filename[k-1] == '/') k--;
	filename[k] = 0;
}

struct inode * get_father_inode(char *dirname)
{
	struct inode* head = root;
	char s[FILE_NAME_LEN];
	int i = 1,j,is_find = 0;
	if(strlen(dirname) == 1)
	{
		return head;
	}
	int len = strlen(dirname);
	if(dirname[len-1] != '/'){
		dirname[len] = '/';  
		dirname[len+1] = 0;  
	} 
	while(1)
	{
		head = head->son;
		if(head == NULL) break;	
		j = 0;	
		while(1){
			s[j++] = dirname[i++];
			if(dirname[i] == '/') 
			{
				s[j] = 0;
				while(1){
					if(strcmp(head->filename,s) == 0) 
					{
						is_find = 1;
						break;//to 1
					}
					head = head -> bro;
					if(head == NULL) return NULL;
				}
			}
			if(is_find == 1) {
				is_find = 0;
				if(!dirname[i+1])
					is_find = 1;
				break;
			}
		}
		if(!dirname[++i]) break;
	}
	if(is_find == 1)
	{
		return head;
	}
	return NULL;
}


int dhmpMknod(const char * path)
{
	struct attr attr;
	if(strlen(path) == 1) return 0;
	char filename[FILE_NAME_LEN],dirname[FILE_NAME_LEN];
	deal(path,dirname,filename);
	struct inode * father = get_father_inode(dirname);
	if(father == NULL) {DEBUG("EROrr path to mknod\n");return -1;}
	{
		char filename[FILE_NAME_LEN];
		int len = strlen(path);
		strcpy(filename,path);
		filename[len] = '/'; filename[len+1] = 0;
		struct inode* head = get_father_inode(filename);
		if(head != NULL)
		{
			DEBUG("dhmpMknod same file fail");
			DEBUG(father->filename);
			DEBUG(filename);
			DEBUG_END();
			return  -1;
		} 
	}
	struct inode * now = malloc(sizeof(struct inode));;
	now -> isDirectories = 0;
	now -> son = NULL;
	now -> bro = NULL;
	now -> size = 0;
	now -> timeLastModified = time(NULL);
	now -> context = NULL;
	memset(now->filename,0,FILE_NAME_LEN);
	strcpy(now->filename,filename);
	struct inode * tmp = father->son;
	DEBUG("Mknod");
    	DEBUG(father->filename);
    	DEBUG(now->filename);
    	DEBUG_END();
	father -> son = now;
	now -> bro = tmp;
	return 1;
	
}

int dhmpCreateDirectory(const char * path)
{
	if(strlen(path) == 1) return 0;
	char filename[FILE_NAME_LEN],dirname[FILE_NAME_LEN];
	deal(path,dirname,filename);

	struct inode * now = malloc(sizeof(struct inode));;
	now -> isDirectories = 1;  
	now -> son = NULL;
	now -> size = 0;
	now -> timeLastModified = time(NULL);
	memset(now->filename,0,FILE_NAME_LEN);
	strcpy(now->filename,filename);
	struct inode * father = get_father_inode(dirname);
	if(father == NULL) return -1;
	if(father->isDirectories == 0) return -1;
	struct inode * tmp = father->son;
	father -> son = now;
	now -> bro = tmp;
	return 1;
}


int dhmpGetAttr(const char *path,struct attr *attr)
{
	char filename[FILE_NAME_LEN];
	int len = strlen(path);
	strcpy(filename,path);
	filename[len] = '/'; filename[len+1] = 0;
	struct inode* head = get_father_inode(filename);
	if(head == NULL) return -1;
	attr->isDirectories = head->isDirectories;
	attr->size = head->size;
	attr->timeLastModified = head->timeLastModified;
	return 0;
}

int dhmpReadDir(const char *path,struct inode_list *Li)
{
	char filename[FILE_NAME_LEN];
	struct inode_list *list=NULL;
	int len = strlen(path);
	Li->isDirectories = -1;
	Li->next = NULL;
	struct inode* head;
	if(len != 1)
	{
		strcpy(filename,path);
		head = get_father_inode(filename);
	}
	else head = root;
	if(head == NULL) return -1;
	head = head->son;
	if(head != NULL)
	{
		Li->isDirectories = head->isDirectories;
		strcpy(Li->filename,head->filename);
		Li->next = NULL;
		head = head->bro;
	}
	list = Li;
	while(head != NULL)
	{
		list->next = malloc(sizeof(struct inode_list));
		list = list->next;
		list->isDirectories = head->isDirectories;
		strcpy(list->filename,head->filename);
		list->next = NULL;
		head = head->bro;
	}
	return 0;
}

void dhmpFreeInode(struct inode * head)
{
	if(head == NULL) return ;
	struct context * context = head->context, *tmp;
	while(context != NULL)
	{
		tmp = context;
		DEBUG("Free chunk");
		DEBUG_INT(tmp->chunk_index );
		DEBUG_END();
		bitmap[tmp->chunk_index] = 0;
		context = context->next;
		free(tmp);
	}
	free(head);
}

void dhmpDeleteALL(struct inode *head)
{
	if(head == NULL) return;
	if(head->bro != NULL)
	{
		dhmpDeleteALL(head->bro);
	}
	if(head->isDirectories == 1 && head->son != NULL)
	{
		dhmpDeleteALL(head->son);
	}
	dhmpFreeInode(head);
}

int dhmpDelFromInode(struct inode *head,char * filename)
{
	struct inode * tmp ,*ttmp;
	tmp = head -> son;
	if(tmp == NULL) return 0;
	if(strcmp(filename,tmp->filename) == 0)
	{
		head -> son = tmp ->bro;
		tmp -> bro = NULL;
		if(tmp->isDirectories == 1)
			dhmpDeleteALL(tmp->son);
		dhmpFreeInode(tmp);
		return 0;
	}
	while(tmp->bro!=NULL)
	{
		ttmp = tmp;
		tmp = tmp->bro;
		if(strcmp(filename,tmp->filename) == 0)
		{
			ttmp -> bro = tmp ->bro;
			tmp->bro = NULL;
			if(tmp->isDirectories == 1)
				dhmpDeleteALL(tmp->son);
			dhmpFreeInode(tmp);
			return 0;
		}
	}
	return -1;
}

int dhmpDelete(const char *path)
{
	if(strlen(path) == 1) return 0;
	char filename[FILE_NAME_LEN],dirname[FILE_NAME_LEN];
	deal(path,dirname,filename);
	struct inode * father = get_father_inode(dirname);
	return dhmpDelFromInode(father,filename);
}

static int dhmp_fs_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	struct attr attr;
	int ret = 0;
	if(strlen(path) == 1)
	{
		attr.size = 0;
		attr.isDirectories = root->isDirectories;
		attr.timeLastModified = root->timeLastModified;
	}
	else 
		ret = dhmpGetAttr(path,&attr);
	if(ret < 0)
		return -2;
	if(attr.isDirectories == 1)
	{
		stbuf->st_mode = S_IFDIR | 0777;
		stbuf->st_size = 0;
	}
	else
	{
		stbuf->st_size = attr.size;
		stbuf->st_mode = S_IFREG | 0777;
	}

    	stbuf->st_nlink = 1;            /* Count of links, set default one link. */
    	stbuf->st_uid = 0;              /* User ID, set default 0. */
    	stbuf->st_gid = 0;              /* Group ID, set default 0. */
    	stbuf->st_rdev = 0;             /* Device ID for special file, set default 0. */
    	stbuf->st_atime = 0;            /* Time of last access, set default 0. */
    	stbuf->st_mtime = attr.timeLastModified; /* Time of last modification, set default 0. */
    	stbuf->st_ctime = 0;            /* Time of last creation or status change, set default 0. */
	return 0;

}

static int dhmp_fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{

	struct inode_list list,*tmp;
	uint32_t i;
	struct stat st;
	dhmpReadDir(path,&list);
	tmp = &list;
	if(tmp->isDirectories == -1) return 0;
	for(; tmp != NULL; tmp = tmp->next)
	{
		memset(&st, 0, sizeof(st));
		st.st_mode = (tmp->isDirectories == 1) ? S_IFDIR : S_IFMT;
		if (filler(buf, tmp->filename, &st, 0,0))
			break;
	}
	return 0;
}



static int dhmp_fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	res = dhmpMknod(path);
	if(res < 0)
		return -1;
	else
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
static int dhmp_fs_rmdir(const char *path)
{
	int res = dhmpDelete(path);
	if(res < 0)
		return -2;
	else 
		return 0;
}


static int dhmp_fs_unlink(const char *path)
{
	int res = dhmpDelete(path);
	if(res < 0)
		return -2;
	else
		return 0;
}


static int dhmp_fs_rename(const char *from, const char *to, unsigned int flags)
{
	char filename[FILE_NAME_LEN],dirname[FILE_NAME_LEN],toname[FILE_NAME_LEN];
	int len = strlen(from);
	strcpy(filename,from);
	filename[len] = '/'; filename[len+1] = 0;
	struct inode* head = get_father_inode(filename);
	if(head == NULL) return -17;
	deal(to,dirname,toname);
	DEBUG(head->filename);
	DEBUG(toname);
	DEBUG_END();
	strcpy(head->filename, toname);
	return 0;
}

static int dhmp_fs_chmod(const char *path, mode_t mode,
		     struct fuse_file_info *fi)
{
	return 0;
}

static int dhmp_fs_chown(const char *path, uid_t uid, gid_t gid,
		     struct fuse_file_info *fi)
{
	return 0;
}

static int dhmp_fs_truncate(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	return 0;
}


static int dhmp_fs_open(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int dhmp_fs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	char *bbuf = malloc(size);
	char filename[FILE_NAME_LEN];
	int len = strlen(path);
	strcpy(filename,path);
	filename[len] = '/'; filename[len+1] = 0;
	struct inode* head = get_father_inode(filename);
	if(head == NULL || head->isDirectories == 1) return -1;

	struct context * cnt = head->context;
	if(cnt == NULL) return 0;
	off_t read_offset = offset;
	int i = read_offset / CHUNK_SIZE;
	while(i > 0)
	{
		if(cnt == NULL || cnt -> size  != CHUNK_SIZE){ DEBUG("dhmp_fs_read error");return 0;}
		cnt = cnt->next;
		i--;
	}
	read_offset = read_offset % CHUNK_SIZE;
	size_t read_size = 0,un_read_size = size;
	while(un_read_size > 0)
	{
		if(cnt == NULL) {DEBUG("dhmp_fs_read eror");break;}
		if(un_read_size >= cnt->size - read_offset){
			dhmp_fs_read_from_bank( cnt->chunk_index, bbuf + read_size, (cnt->size - read_offset), read_offset);
			read_size += cnt->size - read_offset;
			un_read_size = un_read_size - (cnt->size - read_offset);
			read_offset = 0;
		}
		else
		{
			dhmp_fs_read_from_bank( cnt->chunk_index, bbuf + read_size , un_read_size, read_offset);
			read_size += un_read_size;
			un_read_size = 0;
		}
		cnt = cnt->next;
	}
	bbuf[read_size] = 0;
	memcpy(buf,bbuf,read_size);
	free(bbuf);
	return read_size;
}

static int dhmp_fs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;
	char filename[FILE_NAME_LEN];
	int len = strlen(path);
	strcpy(filename,path);
	filename[len] = '/'; filename[len+1] = 0;
	struct inode* head = get_father_inode(filename);
	if(head == NULL || head->isDirectories == 1) return -1;
	struct context * cnt = head->context;
	if(cnt == NULL)
	{
		head->context = malloc(sizeof(struct context));
		cnt = head->context;
		cnt->size = 0;
		cnt->chunk_index = getFreeChunk();
		cnt->next = NULL;
	}
	off_t write_offset = offset;
	int i = write_offset / CHUNK_SIZE;
	write_offset = write_offset % CHUNK_SIZE;
	while(i > 0)
	{
		if(cnt == NULL) return 0;
		if(cnt -> size  != CHUNK_SIZE) return 0;
		i--;
		if(i == 0 && write_offset == 0 && cnt->next == NULL)
		{
			cnt->next = malloc(sizeof(struct context));
			cnt->next->size = 0;
			cnt->next->chunk_index = getFreeChunk();
			cnt->next->next = NULL;
		}
		cnt = cnt->next;
	}
	
	size_t write_size = 0,un_write_size = size;
	while(un_write_size > 0)
	{
		if(un_write_size >= (CHUNK_SIZE - write_offset)){
			dhmp_fs_write_to_bank(cnt->chunk_index, buf + write_size, (CHUNK_SIZE - write_offset), write_offset);
			write_size += (CHUNK_SIZE - write_offset);
			un_write_size = un_write_size - (CHUNK_SIZE - write_offset);
			//head->size += (CHUNK_SIZE - write_offset);
			head->size = head->size - cnt->size + CHUNK_SIZE;
			write_offset = 0;
			cnt->size = CHUNK_SIZE;
			if(cnt->next == NULL && un_write_size > 0)
			{
				cnt->next = malloc(sizeof(struct context));
				cnt->next->size = 0;
				cnt->next->chunk_index = getFreeChunk();
				cnt->next->next = NULL;
			}
		}
		else
		{
			dhmp_fs_write_to_bank(cnt->chunk_index, buf + write_size , un_write_size, write_offset);
			write_size += un_write_size;
			if(cnt->size != CHUNK_SIZE)
			{
				head->size = head->size - cnt->size;
				cnt->size = un_write_size + write_offset;
				head->size += cnt->size;
			}
			un_write_size = 0;
		}
		cnt = cnt->next;
	}
	return size;
}

static int dhmp_fs_statfs(const char *path, struct statvfs *stbuf)
{
	stbuf->f_bsize = BANK_SIZE;
	return 0;
}


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



