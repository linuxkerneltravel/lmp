#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h> 

/*相关数据结构*/

#define FILE_TYPE 1
#define DIRECTORY_TYPE 2


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
};

struct dfs_dentry
{
    char fname[255];
    int ftype;
    struct dfs_dentry *parent;
    struct dfs_dentry *brother;
    struct dfs_dentry *child;
    struct dfs_inode *inode;            //指向对应的inode
};

struct dfs_dentry *root;                    //根节点

/*过程函数*/
static struct dfs_inode *new_inode(uint32_t ino, int size, int dir_cnt)
{
    struct dfs_inode *inode = (struct dfs_inode *)malloc(sizeof(struct dfs_inode));
    inode->ino = ino;
    inode->size = size;
    inode->dir_cnt = dir_cnt;
    inode->data_pointer = NULL;
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
    return dentry;
}

void add_child_dentry(struct dfs_dentry *parent, struct dfs_dentry *child)
{
    child->brother = parent->child;
    parent->child = child;
}

struct dfs_dentry *look_up(struct dfs_dentry *dentrys, const char *path)
{
    struct dfs_dentry *dentry = dentrys;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");
    while (token != NULL && dentry != NULL)
    {
        struct dfs_dentry *child = dentry->child;
        while (child != NULL && strcmp(child->fname, token) != 0)
        {
            child = child->brother;
        }
        dentry = child;
        token = strtok(NULL, "/");
    }

    free(path_copy);
    return dentry;
}


/*功能函数*/

static int di_getattr(const char *path, struct stat *di_stat,
    struct fuse_file_info *fi)
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
static int di_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    (void)offset;
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

/*
确保我们尝试从文件中读取的起始位置（偏移量）在文件范围内。
如果偏移量超出了文件内容的长度，说明请求读取的位置在文件的末尾或之后，这种情况下不能读取任何数据。
*/
static int di_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
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
        memcpy(buf, "dummy_content", size);  // Replace with actual file data handling
    }
    else
        size = 0;

    return size;
}


static struct fuse_operations difs_ops = {
    .readdir = di_readdir,
    .getattr = di_getattr,
    .open = di_open,
    .read = di_read,
    //.mkdir = di_mkdir,
};

int main(int argc, char *argv[])
{
    struct dfs_inode *root_inode = new_inode(1, 0, 2);
    root = new_dentry("/", DIRECTORY_TYPE, NULL, root_inode);

    // 创建dir1目录
    struct dfs_inode *dir1_inode = new_inode(2, 0, 2);
    struct dfs_dentry *dir1 = new_dentry("dir1", DIRECTORY_TYPE, root, dir1_inode);
    add_child_dentry(root, dir1);

    // 创建dir2目录
    struct dfs_inode *dir2_inode = new_inode(3, 0, 1);
    struct dfs_dentry *dir2 = new_dentry("dir2", DIRECTORY_TYPE, root, dir2_inode);
    add_child_dentry(root, dir2);

    // 创建file1文件
    struct dfs_inode *file1_inode = new_inode(4, 100, 0);
    struct dfs_dentry *file1 = new_dentry("file1", FILE_TYPE, dir1, file1_inode);
    add_child_dentry(dir1, file1);

    // 创建file2文件
    struct dfs_inode *file2_inode = new_inode(5, 200, 0);
    struct dfs_dentry *file2 = new_dentry("file2", FILE_TYPE, dir1, file2_inode);
    add_child_dentry(dir1, file2);

    // 创建file3文件
    struct dfs_inode *file3_inode = new_inode(6, 150, 0);
    struct dfs_dentry *file3 = new_dentry("file3", FILE_TYPE, dir2, file3_inode);
    add_child_dentry(dir2, file3);

    return fuse_main(argc, argv, &difs_ops, NULL);
}