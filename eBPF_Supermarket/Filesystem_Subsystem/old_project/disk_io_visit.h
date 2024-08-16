#ifndef DISK_IO_VISIT_H
#define DISK_IO_VISIT_H

#define TASK_COMM_LEN 256

struct event {
    long timestamp; // 时间戳
    int blk_dev; // 块设备号
    int sectors; // 访问的扇区数
    int rwbs; // 读写标识符，1表示读操作，0表示写操作
    int count; // I/O 操作计数
    char comm[TASK_COMM_LEN]; // 进程名
};

#endif // DISK_IO_VISIT_H
