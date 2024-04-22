#ifndef __WRITE_H
#define __WRITE_H

//获取vfs_write各个参数信息
struct fs_t {
    int fd;
    int pid;
    
    size_t real_count;
    size_t count;
};

#endif /* __WRITE_H */