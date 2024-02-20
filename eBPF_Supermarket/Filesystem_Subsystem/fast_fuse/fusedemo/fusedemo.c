

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



#define TOTOL_SIZE ((uint64_t)1024*1024*1024*2)   			/* Size of fusdemo */
#define BANK_SIZE (1024*1024*4)						/* Size of a memory block, set to 4MB */			
#define BANK_NUM (TOTOL_SIZE/BANK_SIZE)					/* Number of memory blocks */
#define CHUNK_SIZE (1024*16)						/* Size of a data block, set to 16KB */
#define CHUNK_NUM (TOTOL_SIZE / CHUNK_SIZE)				/* Number of data blocks */

#define FILE_NAME_LEN 1024						/* Maximum length of file */

struct context
{
	int chunk_index;						/* Identifier for the data block */
	size_t size;							/* Size of the block */
	struct context *next;						/*Next context */
};

struct inode
{
	char filename[FILE_NAME_LEN];					/* Name of the file or directory */
	size_t size;							/* Size of the file */
	time_t timeLastModified;					/* Last modification time */
	char isDirectories;						/* Indicates whether it is a directory (1 for directory, 0 otherwise) */

	struct
	{
		struct context *context;				/* Context information for the file or directory */
	};
	struct
	{
		struct inode *son;					/* Child node */
		struct inode *bro;					/* Brother node */
	};

};

struct attr
{
	int size;							/* Size of the file */
	time_t timeLastModified;					/* Last modification time */
	char isDirectories;						/* Indicates whether it is a directory (1 for directory, 0 otherwise) */
};

struct inode_list
{
	struct inode_list *next;					/* Next directory entry node */
	char isDirectories;						/* Indicates whether it is a directory (1 for directory, 0 otherwise) */
	char filename[FILE_NAME_LEN];					/* File name */
};

void *bank[BANK_NUM];							/* Memory pool */
char *dhmp_local_buf;							/* Local buffer */
struct inode *root;							/* Root node */

FILE *fp;
char msg[1024];
char msg_tmp[1024];							/* DEBUG message */

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
char bitmap[CHUNK_NUM];							/* Allocation status of data blocks (1 for allocated, 0 for free) */

/**
 * Get a free chunk index from data blocks.
 *
 * @return The index of the free chunk.
 */
int getFreeChunk()
{
	int i = 0;
	/* Iterate through the chunk bitmap to find a free chunk */
	for (;i < CHUNK_NUM; i++)
	{
		if (bitmap[i] == 1)continue;
		break;
	}
	if (i == CHUNK_NUM)
		DEBUG("Error:no space for free chunk");
	bitmap[i] = 1;
	DEBUG("getFreeChunk = ");
	DEBUG_INT(i);
	DEBUG_END();
	return i;
}

/**
 * Reads data from Memory pool.
 *
 * @param chunk_index Data block index.
 * @param buf Buffer to store read data.
 * @param size Number of bytes to read.
 * @param chunk_offset Offset within the data block.
 */
void dhmp_fs_read_from_bank(int chunk_index, char *buf, size_t size, off_t chunk_offset)
{
	DEBUG("dhmp_fs_read_from_bank size =");
	DEBUG_INT(size);
	DEBUG("chunk_offset=");
	DEBUG_INT(chunk_offset);

	/* Calculate the position of the data block in the bank */
	void *tbank = (bank[chunk_index / (CHUNK_NUM / BANK_NUM)]);
	int times = chunk_index % (CHUNK_NUM / BANK_NUM);
	off_t offset = chunk_offset + times * CHUNK_SIZE;
	DEBUG("chunk ==  ");
	DEBUG_INT(chunk_index);
	DEBUG("chunkoffset=");
	DEBUG_INT(offset);
	DEBUG_INT(times);

	/**
	* Calculate the actual size of data to be read,
	* Copy data from the bank to the local buffer,
	* Copy data from the local buffer to the output buffer.
	*/
	size_t Tsize = chunk_offset + size + times * CHUNK_SIZE;
	memcpy(dhmp_local_buf, tbank, Tsize);

	memcpy(buf, dhmp_local_buf + offset, size);
}

/**
 * Write data to Memory pool.
 *
 * @param chunk_index Data bank index.
 * @param buf Buffer containing the data to be written.
 * @param size Size of the data to be written.
 * @param chunk_offset Offset within the data bank.
 */
void dhmp_fs_write_to_bank(int chunk_index, char *buf, size_t size, off_t chunk_offset)
{
	DEBUG("dhmp_fs_write_to_bank size =");
	DEBUG_INT(size);
	DEBUG("chunk_offset=");
	DEBUG_INT(chunk_offset);

	/* Calculate the position of the data block in the bank */
	void *tbank = (bank[chunk_index / (CHUNK_NUM / BANK_NUM)]);
	int times = chunk_index % (CHUNK_NUM / BANK_NUM);
	off_t offset = chunk_offset + times * CHUNK_SIZE;
	DEBUG("chunk = =");
	DEBUG_INT(chunk_index);
	DEBUG("chunkoffset=");
	DEBUG_INT(offset);
	DEBUG_INT(times);

	/**
	* Calculate the actual size of data to be written,
	* Copy data from the bank to the local buffer,
	* Copy data from the input buffer to the local buffer,
	* Copy data from the local buffer back to the bank.
	*/
	size_t Tsize = chunk_offset + size + times * CHUNK_SIZE;
	memcpy(dhmp_local_buf, tbank, offset);
	memcpy(dhmp_local_buf + offset, buf, size);
	memcpy(tbank, dhmp_local_buf, Tsize);
}

/**
 * Initialize the FUSE file system.
 *
 * @param conn FUSE connection information.
 * @param cfg FUSE configuration.
 * @return 0 on success, an error code otherwise.
 */
static int dhmp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	/* Initialize the memory pool */
	int init_bank_i;
	for (init_bank_i = 0;init_bank_i < BANK_NUM;init_bank_i++)
		bank[init_bank_i] = malloc(BANK_SIZE);
	/* Initialize the root directory of the file system */
	root = (struct inode *)malloc(sizeof(struct inode));
	root->bro = NULL;
	root->son = NULL;
	root->isDirectories = 1;		/* 1 indicates a directory, 0 indicates a non-directory */
	root->size = 0;
	root->timeLastModified = time(NULL);
	memset(root->filename, 0, FILE_NAME_LEN);
	root->filename[0] = '/';
	/* Initialize the bitmap */
	memset(bitmap, 0, sizeof(bitmap));
	return 0;
}

static int dhmp_fs_access(const char *path, int mask)
{
	return 0;
}

/* brief: deal path to dir/file mode
 *
 * transfaring	(/root/lhd/node)  to (/root/lhd/ node)
 * transfaring 	(/root/lhd/node/) to (/root/lhd/ node)
 * do not do anything with root(/) dir
 */
void deal(const char *path, char *dirname, char *filename)
{
	int i = 0, j = 0, k = 0, m = 0;
	int len = strlen(path);
	for (;i < len;i++)
	{
		dirname[i] = path[i];
		if (path[i] == '/' && path[i + 1] != 0) j = i;
	}
	m = j++;
	for (;j < len;)
	{
		filename[k] = path[j];
		k++;j++;
	}
	dirname[m + 1] = 0;
	if (filename[k - 1] == '/') k--;
	filename[k] = 0;
}

/**
 * Get the parent directory's inode for a given directory path.
 *
 * @param dirname Directory path.
 * @return Inode pointer of the parent directory or NULL on failure.
 */
struct inode *get_father_inode(char *dirname)
{
	/* Initialize the parent directory as the root directory */
	struct inode *head = root;
	char s[FILE_NAME_LEN];
	/* Initialize index variables and search flag */
	int i = 1	/* If the directory path length is 1, return the inode structure pointer of the root directory directly */
	if (strlen(dirname) == 1)
	{
		return head;
	}
	/* If the directory path does not end with '/', add '/' at the end of the path */
	int len = strlen(dirname);
	if (dirname[len - 1] != '/')
	{
		dirname[len] = '/';
		dirname[len + 1] = 0;
	}
	/**
	* Loop through the directory, searching for a subdirectory
	* Process directory names by adding them to an array.
	* If a '/' is encountered, it indicates the end of the directory name.
	* Search for a matching subdirectory in the current directory.
	* If a match is found, exit the loop and return the parent directory pointer.
	*/
	while (1)
	{
		head = head->son;
		if (head == NULL) break;
		j = 0;
		while (1)
		{
			s[j++] = dirname[i++];
			if (dirname[i] == '/')
			{
				s[j] = 0;
				while (1)
				{
					if (strcmp(head->filename, s) == 0)
					{
						is_find = 1;
						break;//to 1
					}
					head = head->bro;
					if (head == NULL) return NULL;
				}
			}
			if (is_find == 1)
			{
				is_find = 0;
				if (!dirname[i + 1])
					is_find = 1;
				break;
			}
		}
		if (!dirname[++i]) break;
	}
	if (is_find == 1)
	{
		return head;
	}
	return NULL;
}

/**
 * Create special file by the given path.
 *
 * @param path The path where the file is to be created.
 * @return Returns 0 if the path is the root directory, 1 if the operation is successful, -1 if it fails.
 */
int dhmpMknod(const char *path)
{
	struct attr attr;
	if (strlen(path) == 1) return 0;
	char filename[FILE_NAME_LEN], dirname[FILE_NAME_LEN];
	deal(path, dirname, filename);
	struct inode *father = get_father_inode(dirname);

	/**
	* This code ensures the parent directory is valid before creating a file,
	* return -1 on failure due to a nonexistent parent directory or an existing file with the same name
	*/
	if (father == NULL) { DEBUG("EROrr path to mknod\n");return -1; }
	{
		char filename[FILE_NAME_LEN];
		int len = strlen(path);
		strcpy(filename, path);
		filename[len] = '/'; filename[len + 1] = 0;
		struct inode *head = get_father_inode(filename);
		if (head != NULL)
		{
			DEBUG("dhmpMknod same file fail");
			DEBUG(father->filename);
			DEBUG(filename);
			DEBUG_END();
			return  -1;
		}
	}
	struct inode *now = malloc(sizeof(struct inode));
	now->isDirectories = 0;
	now->son = NULL;
	now->bro = NULL;
	now->size = 0;
	now->timeLastModified = time(NULL);
	now->context = NULL;
	memset(now->filename, 0, FILE_NAME_LEN);
	strcpy(now->filename, filename);
	struct inode *tmp = father->son;
	DEBUG("Mknod");
	DEBUG(father->filename);
	DEBUG(now->filename);
	DEBUG_END();
	father->son = now;
	now->bro = tmp;
	return 1;

}

/**
 * Create a directory by the given path.
 *
 * @param path The path where the directory is to be created.
 * @return Returns 0 if the path is the root directory, 1 if the operation is successful, -1 if it fails.
 */
int dhmpCreateDirectory(const char *path)
{
	if (strlen(path) == 1) return 0;
	char filename[FILE_NAME_LEN], dirname[FILE_NAME_LEN];
	deal(path, dirname, filename);

	/* Create a new inode for the directory */
	struct inode *now = malloc(sizeof(struct inode));
	now->isDirectories = 1;
	now->son = NULL;
	now->size = 0;
	now->timeLastModified = time(NULL);
	memset(now->filename, 0, FILE_NAME_LEN);
	strcpy(now->filename, filename);
	/* Get the inode of the parent directory */
	struct inode *father = get_father_inode(dirname);
	if (father == NULL) return -1;
	if (father->isDirectories == 0) return -1;
	/* Insert the new directory as a child of the parent */
	struct inode *tmp = father->son;
	father->son = now;
	now->bro = tmp;
	return 1;
}

/**
 * Get the attribute information of a file or directory.
 *
 * @param path The path of the file or directory.
 * @param attr A pointer to the struct (struct attr) for storing attribute information.
 * @return Returns 0 if the operation is successful, a negative value if it fails.
 */
int dhmpGetAttr(const char *path, struct attr *attr)
{
	char filename[FILE_NAME_LEN];
	/* Add a slash at the end of the path to construct the complete file path */
	int len = strlen(path);
	strcpy(filename, path);
	filename[len] = '/'; filename[len + 1] = 0;
	struct inode *head = get_father_inode(filename);
	if (head == NULL) return -1;
	/* Fill the attribute information obtained into the attr struct */
	attr->isDirectories = head->isDirectories;
	attr->size = head->size;
	attr->timeLastModified = head->timeLastModified;
	return 0;
}

/**
 * Read the directory by path and inode_list
 *
 * @param path The path of the directory to read.
 * @param Li   Pointer to the inode list to store the directory contents.
 * @return     Returns 0 on success, -1 on failure.
 */
int dhmpReadDir(const char *path, struct inode_list *Li)
{
	char filename[FILE_NAME_LEN];
	struct inode_list *list = NULL;
	int len = strlen(path);
	/* Initialize the inode list */
	Li->isDirectories = -1;
	Li->next = NULL;
	struct inode *head;
	/* Get the parent inode based on the path */
	if (len != 1)
	{
		strcpy(filename, path);
		head = get_father_inode(filename);
	}
	else head = root;
	if (head == NULL) return -1;
	head = head->son;
	/* If the head node is not empty, copy the information from the head node to the inode list */
	if (head != NULL)
	{
		Li->isDirectories = head->isDirectories;
		strcpy(Li->filename, head->filename);
		Li->next = NULL;
		head = head->bro;
	}
	list = Li;
	/* Copy the head linked list to list linked list */
	while (head != NULL)
	{
		list->next = malloc(sizeof(struct inode_list));
		list = list->next;
		list->isDirectories = head->isDirectories;
		strcpy(list->filename, head->filename);
		list->next = NULL;
		head = head->bro;		/* Move to the next node in the head list */
	}
	return 0;
}

/**
 * Free the given inode and its associated context, releasing allocated resources.
 *
 * @param head The inode to be freed.
 */
void dhmpFreeInode(struct inode *head)
{
	if (head == NULL) return;
	/* Release allocated chunks and associated context */
	struct context *context = head->context, *tmp;
	while (context != NULL)
	{
		tmp = context;
		DEBUG("Free chunk");
		DEBUG_INT(tmp->chunk_index);
		DEBUG_END();
		bitmap[tmp->chunk_index] = 0;
		context = context->next;
		free(tmp);
	}
	free(head);
}

/**
 * Recursively delete all inodes starting from the given inode.
 *
 * @param head  The starting inode for deletion.
 */
void dhmpDeleteALL(struct inode *head)
{
	if (head == NULL) return;
	if (head->bro != NULL)
	{
		dhmpDeleteALL(head->bro);
	}
	if (head->isDirectories == 1 && head->son != NULL)
	{
		dhmpDeleteALL(head->son);
	}
	dhmpFreeInode(head);
}

/**
 * Delete a child inode with the specified filename from the given parent inode.
 *
 * @param head      The parent inode.
 * @param filename  The name of the inode to be deleted.
 * @return          Returns 0 on success, -1 on failure.
 */
int dhmpDelFromInode(struct inode *head, char *filename)
{
	struct inode *tmp, *ttmp;
	tmp = head->son;
	if (tmp == NULL) return 0;
	/* Check if the son's filename matches the specified filename */
	if (strcmp(filename, tmp->filename) == 0)
	{
		head->son = tmp->bro;
		tmp->bro = NULL;
		/* Recursively delete all child inodes if the son is a directory */
		if (tmp->isDirectories == 1)
			dhmpDeleteALL(tmp->son);
		dhmpFreeInode(tmp);
		return 0;
	}
	/* Iterate through the brother inodes */
	while (tmp->bro != NULL)
	{
		ttmp = tmp;
		tmp = tmp->bro;
		if (strcmp(filename, tmp->filename) == 0)
		{
			ttmp->bro = tmp->bro;
			tmp->bro = NULL;
			if (tmp->isDirectories == 1)
				dhmpDeleteALL(tmp->son);
			dhmpFreeInode(tmp);
			return 0;
		}
	}
	return -1;
}

int dhmpDelete(const char *path)
{
	if (strlen(path) == 1) return 0;
	char filename[FILE_NAME_LEN], dirname[FILE_NAME_LEN];
	deal(path, dirname, filename);
	struct inode *father = get_father_inode(dirname);
	return dhmpDelFromInode(father, filename);
}

/**
 * Get the attributes of a file or directory.
 *
 * @param path   Path to the file or directory.
 * @param stbuf  Pointer to the struct stat to store attribute information.
 * @param fi     Pointer to the fuse_file_info struct, can be NULL.
 * @return       Returns 0 on success or a negative value on failure.
 */
static int dhmp_fs_getattr(const char *path, struct stat *stbuf,
	struct fuse_file_info *fi)
{
	/* Structure to store file or directory attribute information */
	struct attr attr;
	int ret = 0;
	/* Check if the path is the root directory */
	if (strlen(path) == 1)
	{
		attr.size = 0;
		attr.isDirectories = root->isDirectories;
		attr.timeLastModified = root->timeLastModified;
	}
	else
		ret = dhmpGetAttr(path, &attr);
	if (ret < 0)
		return -2;
	/* Set the struct stat based on the attribute information */
	if (attr.isDirectories == 1)
	{
		stbuf->st_mode = S_IFDIR | 0777;
		stbuf->st_size = 0;
	}
	else
	{
		stbuf->st_size = attr.size;
		stbuf->st_mode = S_IFREG | 0777;
	}

	stbuf->st_nlink = 1;            			/* Count of links, set default one link. */
	stbuf->st_uid = 0;              			/* User ID, set default 0. */
	stbuf->st_gid = 0;              			/* Group ID, set default 0. */
	stbuf->st_rdev = 0;             			/* Device ID for special file, set default 0. */
	stbuf->st_atime = 0;            			/* Time of last access, set default 0. */
	stbuf->st_mtime = attr.timeLastModified; 		/* Time of last modification, set default 0. */
	stbuf->st_ctime = 0;            			/* Time of last creation or status change, set default 0. */
	return 0;

}

/**
 * Read the contents of a directory.
 *
 * @param path      The path to the directory.
 * @param buf       Buffer to store the directory entries.
 * @param filler    Function to add directory entries to the buffer.
 * @param offset    Offset in the directory to start reading from.
 * @param fi        File information struct.
 * @return          Returns 0 on success or a negative value on error.
 */
static int dhmp_fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
{

	struct inode_list list, *tmp;
	uint32_t i;
	struct stat st;
	dhmpReadDir(path, &list);
	tmp = &list;
	if (tmp->isDirectories == -1) return 0;
	/* Iterate through the directory entries */
	for (; tmp != NULL; tmp = tmp->next)
	{
		memset(&st, 0, sizeof(st));
		st.st_mode = (tmp->isDirectories == 1) ? S_IFDIR : S_IFMT;
		/* Add directory entry to the buffer */
		if (filler(buf, tmp->filename, &st, 0, 0))
			break;
	}
	return 0;
}

static int dhmp_fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	res = dhmpMknod(path);
	if (res < 0)
		return -1;
	else
		return 0;
}

static int dhmp_fs_mkdir(const char *path, mode_t mode)
{
	int res = dhmpCreateDirectory(path);
	if (res < 0)
		return -1;
	else
		return 0;
}

static int dhmp_fs_rmdir(const char *path)
{
	int res = dhmpDelete(path);
	if (res < 0)
		return -2;
	else
		return 0;
}

static int dhmp_fs_unlink(const char *path)
{
	int res = dhmpDelete(path);
	if (res < 0)
		return -2;
	else
		return 0;
}

/**
 * Rename a file or directory.
 *
 * @param from      The path of the source file or directory.
 * @param to        The path of the destination file or directory.
 * @param flags     Flags to control the behavior of the operation.
 * @return          Returns 0 on success or a negative value on error.
 */
static int dhmp_fs_rename(const char *from, const char *to, unsigned int flags)
{
	char filename[FILE_NAME_LEN], dirname[FILE_NAME_LEN], toname[FILE_NAME_LEN];
	int len = strlen(from);
	/* Construct the path of the source file or directory */
	strcpy(filename, from);
	filename[len] = '/'; filename[len + 1] = 0;

	struct inode *head = get_father_inode(filename);
	if (head == NULL) return -17;
	/* Extract directory and filename from the destination path */
	deal(to, dirname, toname);

	DEBUG(head->filename);
	DEBUG(toname);
	DEBUG_END();
	/* Rename the source file or directory */
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

static int find_inode_in_directory(struct inode *parent, const char *name)
{
	struct inode *current = parent->son;
	while (current != NULL)
	{
		if (strcmp(current->filename, name) == 0)
		{
			return 1;
		}
		current = current->bro;
	}

	return 0;
}

static int dhmp_fs_open(const char *path, struct fuse_file_info *fi)
{
	struct inode *father = get_father_inode(path);
	int flag;
	if (father == NULL) return -1;
	if (father->isDirectories == 0) return -1;
	flag = find_inode_in_directory(father, path);
	if (flag)
	{
		printf("文件存在，可以打开");
		return 1;
	}//文件存在
	else return 0;		//文件不存在
}

/**
 * Read data from file.
 *
 * @param path      The path to the file.
 * @param buf       Buffer to store the read data.
 * @param size      Number of bytes to read.
 * @param offset    Offset in the file to start reading from.
 * @param fi        File information struct.
 * @return          Returns the number of bytes read or a negative value on error.
 */
static int dhmp_fs_read(const char *path, char *buf, size_t size, off_t offset,
	struct fuse_file_info *fi)
{
	char *bbuf = malloc(size);
	char filename[FILE_NAME_LEN];
	int len = strlen(path);
	strcpy(filename, path);
	filename[len] = '/'; filename[len + 1] = 0;
	struct inode *head = get_father_inode(filename);
	/**
	* If getting the inode fails or the file is a directory,
	* free the temporary buffer and return error code
	*/
	if (head == NULL || head->isDirectories == 1)
	{
		free(bbuf);
		return -1;
	}

	struct context *cnt = head->context;
	if (cnt == NULL) return 0;
	/* Locate the chunk to read */
	off_t read_offset = offset;
	int i = read_offset / CHUNK_SIZE;
	while (i > 0)
	{
		if (cnt == NULL || cnt->size != CHUNK_SIZE) { DEBUG("dhmp_fs_read error");return 0; }
		cnt = cnt->next;
		i--;
	}
	read_offset = read_offset % CHUNK_SIZE;
	/* Read data chunk by chunk */
	size_t read_size = 0, un_read_size = size;
	while (un_read_size > 0)
	{
		if (cnt == NULL) { DEBUG("dhmp_fs_read eror");break; }

		/**
		 * If the remaining data to read is greater than or equal to the remaining data in the current chunk,
		 * read data from the bank to the buffer. Increase the total read size by adding the remaining size in the
		 * current chunk, decrease the remaining size to read, and reset the read offset to start from the beginning
		 * 	of the next chunk.
		 */
		if (un_read_size >= cnt->size - read_offset)
		{
			dhmp_fs_read_from_bank(cnt->chunk_index, bbuf + read_size, (cnt->size - read_offset), read_offset);
			read_size += cnt->size - read_offset;
			un_read_size = un_read_size - (cnt->size - read_offset);
			read_offset = 0;
		}
		/**
		 * If the remaining data to read is less than the remaining data in the current chunk,
		 * read data from the bank to the buffer. Increase the total read size by adding the remaining size to read,
		 * and reset the un_read_size to start from the beginning of the next chunk.
		 */
		else
		{
			dhmp_fs_read_from_bank(cnt->chunk_index, bbuf + read_size, un_read_size, read_offset);
			read_size += un_read_size;
			un_read_size = 0;
		}
		cnt = cnt->next;
	}
	bbuf[read_size] = 0;
	memcpy(buf, bbuf, read_size);			/* Copy the read data to the output buffer */
	free(bbuf);
	return read_size;
}

/**
 * Write data to file.
 *
 * @param path The path of the file.
 * @param buf The buffer containing the data to be written.
 * @param size The size of the data to be written.
 * @param offset The offset where the data should be written.
 * @param fi File information struct (not used in this implementation).
 * @return The number of bytes written on success, or -1 on failure.
 */
static int dhmp_fs_write(const char *path, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	int res;
	char filename[FILE_NAME_LEN];
	int len = strlen(path);
	strcpy(filename, path);
	filename[len] = '/'; filename[len + 1] = 0;
	struct inode *head = get_father_inode(filename);
	if (head == NULL || head->isDirectories == 1) return -1;
	struct context *cnt = head->context;
	/**
	* If the context of the file is NULL,
	* allocate new context for the file,
	* initialize its properties, and assign a free chunk index.
	*/
	if (cnt == NULL)
	{
		head->context = malloc(sizeof(struct context));
		cnt = head->context;
		cnt->size = 0;
		cnt->chunk_index = getFreeChunk();
		cnt->next = NULL;
	}
	/* Calculate the position of the starting offset for writing in the file's data block. */
	off_t write_offset = offset;
	int i = write_offset / CHUNK_SIZE;
	write_offset = write_offset % CHUNK_SIZE;
	/* Iterate through chunks to find the one corresponding to the offset for writing, create a new chunk if needed. */
	while (i > 0)
	{
		if (cnt == NULL) return 0;
		if (cnt->size != CHUNK_SIZE) return 0;
		i--;
		if (i == 0 && write_offset == 0 && cnt->next == NULL)
		{
			cnt->next = malloc(sizeof(struct context));
			cnt->next->size = 0;
			cnt->next->chunk_index = getFreeChunk();
			cnt->next->next = NULL;
		}
		cnt = cnt->next;
	}

	size_t write_size = 0, un_write_size = size;
	while (un_write_size > 0)
	{
		/**
		 * If the size of the data to be written is greater than or equal to the remaining space in the current block:
		 * Write the data to the current block, increase the file size, and reduce the remaining size to be written.
		 * Update the file size by subtracting the current block size and adding the standard block size.
		 * Reset the write offset and set the current block size to the standard block size.
		 * If the current block is the last one and there is still remaining data, create a new block.
		 */
		if (un_write_size >= (CHUNK_SIZE - write_offset))
		{
			dhmp_fs_write_to_bank(cnt->chunk_index, buf + write_size, (CHUNK_SIZE - write_offset), write_offset);
			write_size += (CHUNK_SIZE - write_offset);
			un_write_size = un_write_size - (CHUNK_SIZE - write_offset);
			//head->size += (CHUNK_SIZE - write_offset);
			head->size = head->size - cnt->size + CHUNK_SIZE;
			write_offset = 0;
			cnt->size = CHUNK_SIZE;
			if (cnt->next == NULL && un_write_size > 0)
			{
				cnt->next = malloc(sizeof(struct context));
				cnt->next->size = 0;
				cnt->next->chunk_index = getFreeChunk();
				cnt->next->next = NULL;
			}
		}
		/**
		 * If the size of the data to be written is less than the remaining space in the current block:
		 * write the data to the current block, update sizes,
		 * If the current block is not full,update file size.
		 */
		else
		{
			dhmp_fs_write_to_bank(cnt->chunk_index, buf + write_size, un_write_size, write_offset);
			write_size += un_write_size;
			if (cnt->size != CHUNK_SIZE)
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
	.init = dhmp_init,            		/* Initialize the file system */
	.getattr = dhmp_fs_getattr,      	/* Get file attributes */
	.access = dhmp_fs_access,       	/* Check file access permissions */
	.readdir = dhmp_fs_readdir,      	/* Read directory contents */
	.mknod = dhmp_fs_mknod,        		/* Create a node */
	.mkdir = dhmp_fs_mkdir,        		/* Create a directory */
	.unlink = dhmp_fs_unlink,       	/* Delete a file */
	.rmdir = dhmp_fs_rmdir,        		/* Delete a directory */
	.rename = dhmp_fs_rename,       	/* Rename a file or directory */
	.chmod = dhmp_fs_chmod,        		/* Modify file permissions */
	.chown = dhmp_fs_chown,        		/* Modify file owner */
	.truncate = dhmp_fs_truncate,     	/* Truncate a file */
	.open = dhmp_fs_open,         		/* Open a file */
	.read = dhmp_fs_read,         		/* Read file content */
	.write = dhmp_fs_write,        		/* Write file content */
	.statfs = dhmp_fs_statfs,       	/* Get file system statistics */
};

int main(int argc, char *argv[])
{
	/* Allocate local buffer */
	dhmp_local_buf = malloc(BANK_SIZE + 1);
#ifdef DEBUG_ON
	fp = fopen(DEBUG_FILE, "ab+");
#endif
	/* Call the fuse_main function to start the FUSE file system */
	int ret = fuse_main(argc, argv, &dhmp_fs_oper, NULL);
	return ret;
}



