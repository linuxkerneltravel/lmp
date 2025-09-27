#ifndef CPU_H
#define CPU_H

#include <asm/types.h>
#include <linux/version.h>

typedef unsigned long long u64;
typedef unsigned int u32;

#define __user
#define MAX_CPU_NR 128
#define TASK_COMM_LEN 20
#define MAX_ENTRIES 102400 // map容量

/*----------------------------------------------*/
/*          一些maps结构体的宏定义                */
/*----------------------------------------------*/
/// @brief 创建一个指定名字和键值类型的ebpf数组
/// @param name 新散列表的名字
/// @param type1 键的类型
/// @param type2 值的类型
/// @param MAX_ENTRIES map容量
#define BPF_ARRAY(name, type1, type2, MAX_ENTRIES) \
	struct { \
		__uint(type, BPF_MAP_TYPE_ARRAY); \
		__uint(key_size, sizeof(type1)); \
		__uint(value_size, sizeof(type2)); \
		__uint(max_entries, MAX_ENTRIES); \
	} name SEC(".maps")
/// @brief 创建一个指定名字和键值类型的ebpf散列表
/// @param name 新散列表的名字
/// @param type1 键的类型
/// @param type2 值的类型
/// @param MAX_ENTRIES 哈希map容量
#define BPF_HASH(name, type1, type2, MAX_ENTRIES) \
	struct { \
		__uint(type, BPF_MAP_TYPE_HASH); \
		__uint(key_size, sizeof(type1)); \
		__uint(value_size, sizeof(type2)); \
		__uint(max_entries, MAX_ENTRIES); \
	} name SEC(".maps")
/// @brief 创建一个指定名字和键值类型的ebpf每CPU数组
/// @param name 新散列表的名字
/// @param type1 键的类型
/// @param type2 值的类型
/// @param MAX_ENTRIES map容量
#define BPF_PERCPU_ARRAY(name, type1, type2, MAX_ENTRIES) \
	struct { \
		__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
		__uint(key_size, sizeof(type1)); \
		__uint(value_size, sizeof(type2)); \
		__uint(max_entries, MAX_ENTRIES); \
	} name SEC(".maps")
/// @brief 创建一个指定名字和键值类型的ebpf每CPU散列表
/// @param name 新散列表的名字
/// @param type1 键的类型
/// @param type2 值的类型
/// @param MAX_ENTRIES map容量
#define BPF_PERCPU_HASH(name, type1, type2, MAX_ENTRIES) \
	struct { \
		__uint(type, BPF_MAP_TYPE_PERCPU_HASH); \
		__uint(key_size, sizeof(type1)); \
		__uint(value_size, sizeof(type2)); \
		__uint(max_entries, MAX_ENTRIES); \
	} name SEC(".maps")


/*----------------------------------------------*/
/*         schedule_delay相关结构体                     */
/*----------------------------------------------*/
//标识不同进程
struct proc_id {
	int pid;
	int cpu_id;
}; 
//标识该进程的调度信息
struct schedule_event {
	int pid;
	int count;//调度次数
	unsigned long long enter_time;
};
//整个系统所有调度信息
struct sum_schedule {
	unsigned long long sum_count;
	unsigned long long sum_delay;
	unsigned long long max_delay;
	unsigned long long min_delay;
    char proc_name_max[TASK_COMM_LEN];
	char proc_name_min[TASK_COMM_LEN];
};

struct proc_schedule {
	struct proc_id id;
	unsigned long long delay;
	char proc_name[TASK_COMM_LEN];
};

struct proc_info {
    pid_t pid;
    char comm[TASK_COMM_LEN];
};

struct proc_history {
    struct proc_info last[2]; // 存储最后两个调度的进程信息
};

#endif // CPU_H