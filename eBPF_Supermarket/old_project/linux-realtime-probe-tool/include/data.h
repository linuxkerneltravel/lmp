#ifndef DATA_H
#define DATA_H

/* 该文件定义xa中保存的数据结构,主要有task_info,以及文件相关file_list及file_node*/
/* lock相关的lock_list及lock_info,stack_info*/

#include "lib.h"
#include "kprobe.h"

#define MAX_FILE_LEN    256

#define IS_SOCK         0x1

/* 当检测到是sock类型时填充,由file_node的private_data指向 */
// struct sock_private {
//     __u16       sk_num;
//     __be16      sk_dport;
//     __be32      sk_daddr;
//     __be32      sk_rcv_saddr;
//     u16         sk_protocol;
// };

/* 内嵌在task_info中,open_fds可以快速判断是否新打开了文件 */
struct file_list {
    unsigned long       open_fds;
    struct list_head    head;
};

/* 列表结点node,文件名file_name,flag表示是否是特殊类型,private私有指针*/
struct file_node {
    struct list_head    node;
    char                file_name[MAX_FILE_LEN];
    unsigned int        f_flags;
    void *              private_data;
};

/* 内嵌在task_info中,total_num和total_time分别是持有锁次数及时间 */
struct lock_list {
    spinlock_t		    lock;
    unsigned int        total_num;
    unsigned long       total_time;
    struct list_head    head;
};

/* 具体到具体一个lock地址的持有次数及时间 */
struct lock_info {
    unsigned int        lock_num;
    unsigned long       lock_time;
    unsigned long       lock_time_stamp;
    unsigned long       lock_addr;
    unsigned int	    num_entries;
    unsigned long	    stack_entries[NUM_STACK_ENTRIES];
    struct timer_list	timer;
    struct lock_list	*lock_list;
    struct list_head	 node;
};

/* 堆栈的保存,与lock关联 */
/*
struct stack_info {
    struct list_head    node;
    unsigned int        num_entries;
    unsigned long       stack_entries[NUM_STACK_ENTRIES];
};
*/

/* task_info */
struct task_info {
    unsigned int                pid;
    unsigned int                cpu;
    char                        comm[TASK_COMM_LEN];
    char                        exe[MAX_FILE_LEN];
    struct rw_semaphore         sem;
    struct file_list            files;
    struct lock_list            locks;
};

/* init_task_info用于填充及初始化一个task_info的元数据->被work的处理函数调用*/
/* update_task_info调用此函数会持有写锁,修改文件及lock信息->被work的处理函数调用*/
/* free_task_info用于释放task_info->释放整个xa时调用,也是在work中被调用 */
extern void init_task_info(struct task_info *task_info, struct kp_info *kp_info);
extern void update_task_info(struct task_info *task_info, struct kp_info *kp_info);
extern void free_task_info(struct task_info *task);

#endif
