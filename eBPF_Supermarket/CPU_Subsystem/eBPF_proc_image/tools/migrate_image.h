#include <asm/types.h>
#include <linux/version.h>

typedef unsigned long long u64;
typedef unsigned int u32;
/*----------------------------------------------*/
/*         migrate_event结构体                     */
/*----------------------------------------------*/
#define MAX_MIGRATE 1024
#define PAGE_SHIFT 13
// #define ARRY_OVERFLOW -1
struct minfo_key{
	pid_t pid;
	int count;
};
struct per_migrate{//每次迁移,记录该次迁移信息;
	u64 time;
	u32 orig_cpu;
	u32 dest_cpu;
	
	u64 orig_cpu_load;//cfs->avg.runnale_avg 就绪队列所有调度实体；量化负载总和
	u64 dest_cpu_load;
	int cpu_capacity;//计算机算力
	int cpu_capacity_orig;//额定算力
	u64 cpu_load_avg;
	u64 pload_avg;
	u64 putil_avg;

	int on_cpu;
    u64 mem_usage;
    u64 read_bytes;
	u64 write_bytes;
	// u64 syscr;
	// u64 syscw;
    u64 context_switches;
    u64 runtime;
};
//每个进程的迁移信息;
struct migrate_event{
	int erro;
	pid_t pid;
	int prio;
	int count,rear;//迁移频率
	//struct per_migrate *migrate_info;//该进程每次迁移信息;
};
