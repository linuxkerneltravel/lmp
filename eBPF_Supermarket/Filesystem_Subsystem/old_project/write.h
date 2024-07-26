#ifndef __WRITE_H
#define __WRITE_H

struct fs_t {
    unsigned long inode_number;
    pid_t pid;
    size_t real_count;
    size_t count;
};

#endif /* __WRITE_H */