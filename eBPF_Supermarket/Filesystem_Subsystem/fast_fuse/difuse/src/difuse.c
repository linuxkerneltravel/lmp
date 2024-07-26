#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

/*相关数据结构*/

#define FILE_TYPE 1
#define DIRECTORY_TYPE 2
#define MAX_INODES 1000  //最大 inode 数量
#define HASH_SIZE 1024

uint32_t next_ino = 1;

struct dfs_data
{
    int chunk_size;
    size_t size;
    struct dfs_data *next;
};

struct dfs_inode
{
    uint32_t ino;                       //inode编号
    int size;                           //文件大小
    int dir_cnt;                        // 如果是目录类型文件，下面有几个目录项
    struct dfs_data *data_pointer;      //指向数据块的指针
    struct dfs_inode *prev;  // LRU 链表前驱指针
    struct dfs_inode *next;  // LRU 链表后继指针
};

struct dfs_dentry
{
    char fname[255];
    int ftype;
    struct dfs_dentry *parent;
    struct dfs_dentry *brother;
    struct dfs_dentry *child;
    struct dfs_inode *inode;            //指向对应的inode
    struct dfs_dentry *prev;            //LRU 链表前驱指针
    struct dfs_dentry *next;            //LRU 链表后继指针
};

struct dfs_dentry *root;                    //根节点
struct dfs_dentry *lru_head = NULL;         //LRU 链表头
struct dfs_dentry *lru_tail = NULL;         //LRU 链表尾
struct dfs_dentry *hash_table[HASH_SIZE];   //哈希表

/*缓存管理*/

static unsigned int hash(const char *path)
{
    unsigned int hash = 0;
    while (*path)
    {
        hash = (hash << 5) + *path++;
    }
    return hash % HASH_SIZE;
}

static void lru_remove(struct dfs_dentry *dentry)
{
    if (dentry->prev)
    {
        dentry->prev->next = dentry->next;
    }
    else
    {
        lru_head = dentry->next;
    }
    if (dentry->next)
    {
        dentry->next->prev = dentry->prev;
    }
    else
    {
        lru_tail = dentry->prev;
    }
}

static void lru_insert(struct dfs_dentry *dentry)
{
    dentry->next = lru_head;
    dentry->prev = NULL;
    if (lru_head)
    {
        lru_head->prev = dentry;
    }
    lru_head = dentry;
    if (!lru_tail)
    {
        lru_tail = dentry;
    }
}

static void lru_access(struct dfs_dentry *dentry)
{
    lru_remove(dentry);
    lru_insert(dentry);
}

static void lru_evict()
{
    if (lru_tail)
    {
        struct dfs_dentry *evict = lru_tail;
        lru_remove(evict);
        unsigned int index = hash(evict->fname);
        hash_table[index] = NULL;
        free(evict->inode);
        free(evict);
    }
}

/*过程函数*/
static struct dfs_inode *new_inode(int size, int dir_cnt)
{
    struct dfs_inode *inode = (struct dfs_inode *)malloc(sizeof(struct dfs_inode));
    inode->ino = next_ino++;
    inode->size = size;
    inode->dir_cnt = dir_cnt;
    inode->data_pointer = NULL;
    inode->prev = NULL;
    inode->next = NULL;
    return inode;
}

static struct dfs_dentry *new_dentry(char *fname, int ftype, struct dfs_dentry *parent, struct dfs_inode *inode)
{
    struct dfs_dentry *dentry = (struct dfs_dentry *)malloc(sizeof(struct dfs_dentry));
    strcpy(dentry->fname, fname);
    dentry->inode = inode;
    dentry->brother = NULL;
    dentry->parent = parent;
    dentry->child = NULL;
    dentry->ftype = ftype;
    dentry->prev = NULL;
    dentry->next = NULL;
    return dentry;
}

void add_child_dentry(struct dfs_dentry *parent, struct dfs_dentry *child)
{
    child->brother = parent->child;
    parent->child = child;
}

struct dfs_dentry *traverse_path(struct dfs_dentry *start_dentry, const char *path, int ftype, int create)
{
    struct dfs_dentry *dentry = start_dentry;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");

    while (token != NULL)
    {
        struct dfs_dentry *child = dentry->child;
        while (child != NULL && strcmp(child->fname, token) != 0)
        {
            child = child->brother;
        }

        if (child == NULL)
        {
            if (create)
            {
                struct dfs_inode *new_inodes = new_inode(0, 0); // 创建新的 inode
                child = new_dentry(token, ftype, dentry, new_inodes); // 创建新的目录项
                add_child_dentry(dentry, child); // 将新目录项添加到父目录项的子目录列表中
            }
            else
            {
                free(path_copy);
                return NULL;
            }
        }

        dentry = child;
        token = strtok(NULL, "/");
    }

    free(path_copy);
    return dentry;
}

struct dfs_dentry *look_up(struct dfs_dentry *dentrys, const char *path)
{
    return traverse_path(dentrys, path, 0, 0);
}

struct dfs_dentry *lookup_or_create_dentry(const char *path, struct dfs_dentry *start_dentry, int ftype)
{
    unsigned int index = hash(path);
    struct dfs_dentry *dentry = hash_table[index];

    if (dentry)
    {
        lru_access(dentry);
        return dentry;
    }

    dentry = traverse_path(start_dentry, path, ftype, 1);
    if (dentry)
    {
        lru_insert(dentry);
        hash_table[index] = dentry;
        if (next_ino > MAX_INODES)
        {
            lru_evict();
        }
    }

    return dentry;
}


/*功能函数*/
static int di_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
    (void)fi;
    struct dfs_dentry *dentry = look_up(root, path);
    if (dentry == NULL)
    {
        return -ENOENT;
    }

    return 0;
}

static int di_mkdir(const char *path, mode_t mode)
{
    (void)mode;
    struct dfs_dentry *dentry = lookup_or_create_dentry(path, root, DIRECTORY_TYPE);
    if (dentry == NULL)
    {
        return -ENOENT;
    }

    return 0;
}

static int dfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)mode;
    (void)fi;
    struct dfs_dentry *existing = look_up(root, path);
    if (existing != NULL)
    {
        return -EEXIST;  // 文件已存在，返回错误
    }
    struct dfs_dentry *dentry = lookup_or_create_dentry(path, root, FILE_TYPE);
    if (dentry == NULL)
    {
        return -ENOENT;
    }

    return 0;
}

static int di_getattr(const char *path, struct stat *di_stat, struct fuse_file_info *fi)
{
    (void)fi;
    int ret = 0;
    memset(di_stat, 0, sizeof(struct stat));

    struct dfs_dentry *dentry = look_up(root, path);
    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype == DIRECTORY_TYPE)
    {
        di_stat->st_mode = S_IFDIR | 0755;
        di_stat->st_nlink = 2;
    }
    else if (dentry->ftype == FILE_TYPE)
    {
        di_stat->st_mode = S_IFREG | 0644;
        di_stat->st_nlink = 1;
        di_stat->st_size = dentry->inode->size;
    }

    return ret;
}

/*遍历目录项*/
static int di_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    (void)fi;
    (void)offset;
    (void)flags;
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype != DIRECTORY_TYPE)
        return -ENOTDIR;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    struct dfs_dentry *child = dentry->child;
    while (child != NULL)
    {
        filler(buf, child->fname, NULL, 0, 0);
        child = child->brother;
    }

    return 0;
}

static int di_open(const char *path, struct fuse_file_info *fi)
{
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype != FILE_TYPE)
        return -EISDIR;

    return 0;
}

static int di_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype != FILE_TYPE)
        return -EISDIR;

    if (offset < dentry->inode->size)
    {
        if (offset + size > dentry->inode->size)
            size = dentry->inode->size - offset;
        memcpy(buf, "dummy_content", size);
    }
    else
        size = 0;

    return size;
}

static void *di_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void)conn;

    // 创建并初始化根目录的 inode 和 dentry
    struct dfs_inode *root_inode = new_inode(0, 0);
    root = new_dentry("/", DIRECTORY_TYPE, NULL, root_inode);

    return 0;
}

static struct fuse_operations difs_ops = {
    .init = di_init,
    .readdir = di_readdir,
    .getattr = di_getattr,
    .open = di_open,
    .read = di_read,
    .mkdir = di_mkdir,
    .create = dfs_create,
    .utimens = di_utimens,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &difs_ops, NULL);
}