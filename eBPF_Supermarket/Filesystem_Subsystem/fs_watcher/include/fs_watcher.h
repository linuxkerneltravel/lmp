#ifndef __FS_WATCHER_H
#define __FS_WATCHER_H

/*open*/
#define path_size 256
#define TASK_COMM_LEN 16

struct event_open {
	int pid_;
	char path_name_[path_size];
	int n_;
    char comm[TASK_COMM_LEN];
};

/*read*/

struct event_read {
	int pid;
    unsigned long long duration_ns;
};

/*write*/
struct fs_t {
   unsigned long inode_number;
    pid_t pid;
    size_t real_count;
    size_t count;
};

/*disk_io_visit*/
struct event_disk_io_visit {
    long timestamp; // 时间戳
    int blk_dev; // 块设备号
    int sectors; // 访问的扇区数
    int rwbs; // 读写标识符，1表示读操作，0表示写操作
    int count; // I/O 操作计数
    char comm[TASK_COMM_LEN]; // 进程名
};

/*block_rq_issue*/
struct event_block_rq_issue {
    long timestamp;       // 时间戳
    int dev;           // 设备号
    int sector;         // 扇区号
    int nr_sectors;     // 扇区数
    char comm[TASK_COMM_LEN]; // 进程名
    int total_io; //I/O总大小
};

#endif /* __MEM_WATCHER_H */