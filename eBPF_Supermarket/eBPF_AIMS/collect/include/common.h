#ifndef __COMMON_H
#define __COMMON_H


typedef uint64_t u64;
typedef uint32_t u32;

#define TASK_COMM_LEN 16

struct event {
    u64 ts;              // 时间戳
    u32 pid;             // 进程号
    u32 tgid;            // 线程组ID
    char comm[TASK_COMM_LEN];
    u32 type;            // 事件类型 (0=CPU, 1=Memory, 2=IO)
    u64 val;             // 对应的事件值
};

#endif
