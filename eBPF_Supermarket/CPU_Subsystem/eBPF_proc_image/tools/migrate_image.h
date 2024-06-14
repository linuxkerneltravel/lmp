#include <asm/types.h>
#include <linux/version.h>

typedef unsigned long long u64;
typedef unsigned int u32;
/*----------------------------------------------*/
/*         migrate_event结构体                     */
/*----------------------------------------------*/
#define MAX_MIGRATE 16
// #define ARRY_OVERFLOW -1
struct per_migrate{//每次迁移,记录该次迁移信息;
	u64 time;
	u32 orig_cpu;
	u32 dest_cpu;
};
//每个进程的迁移信息;
struct migrate_event{
	int erro;
	pid_t pid;
	int prio;
	int count,rear;//迁移频率
	struct per_migrate migrate_info[MAX_MIGRATE];//该进程每次迁移信息;
};
