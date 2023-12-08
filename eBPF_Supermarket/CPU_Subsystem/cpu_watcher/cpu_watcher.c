// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: zhangziheng0525@163.com
//
// user-mode code for libbpf sar

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <argp.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "cpu_watcher.skel.h"
#include "cpu_watcher.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define __ATTACH_KPROBE(skel, sym_name, prog_name, is_retprobe)  \
    do                                                           \
    {                                                            \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,                \
                    .retprobe = is_retprobe,                     \
                    .func_name = #sym_name);                     \
        skel->links.prog_name = bpf_program__attach_kprobe_opts( \
            skel->progs.prog_name,                               \
            0,                                                 \
            object,                                              \
            0,                                                   \
            &uprobe_opts);                                       \
    } while (false)
#define __CHECK_PROGRAM(skel, prog_name)                                                      \
    do                                                                                        \
    {                                                                                         \
        if (!skel->links.prog_name)                                                           \
        {                                                                                     \
            fprintf(stderr, "[%s] no program attached for" #prog_name "\n", strerror(errno)); \
            return -errno;                                                                    \
        }                                                                                     \
    } while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do                                                                  \
    {                                                                   \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
        __CHECK_PROGRAM(skel, prog_name);                               \
    } while (false)


#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)
//选择性挂载

typedef long long unsigned int u64;
typedef unsigned int u32;
static volatile bool exiting = false;//全局变量，表示程序是否正在退出

struct cpu_watcher_bpf *skel;//用于自行加载和运行BPF程序的结构体，由libbpf自动生成并提供与之关联的各种功能接口；
u64 softirq = 0;//初始化softirq;
u64 irqtime = 0;//初始化irq;
u64 idle = 0;//初始化idle;
u64 sched = 0;
u64 proc = 0;
unsigned long ktTime = 0;
unsigned long utTime = 0;

// sar 工具的参数设置
static struct env {
	int time;
	bool enable_proc;
	bool libbpf_sar;
	bool cs_delay;

} env = {
	.time = 0,
	.enable_proc = false,
	.libbpf_sar = false,
	.cs_delay = false,
};

/*设置传参*/
const char argp_program_doc[] ="cpu wacher is in use ....\n";
static const struct argp_option opts[] = {
	{ "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{"libbpf_sar", 's',	0,0,"print sar_info (the data of cpu)"},
	{"cs_delay", 'c',	0,0,"print cs_delay (the data of cpu)"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
	{0},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 't':
			env.time = strtol(arg, NULL, 10);
			if(env.time) alarm(env.time);
                	break;
		case 's':
			env.libbpf_sar = true;
			break;
		case 'c':
			env.cs_delay = true;
			break;			
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};


static void sig_handler(int sig)//信号处理函数
{
	exiting = true;
}//正在退出程序；


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/*-----------------------------------------------------------------------------------------------------*/
/*                         cs_delay处理函数                                                             */
/*-----------------------------------------------------------------------------------------------------*/
int count[25]={0};//定义一个count数组，用于汇总schedul()调度时间，以log2(时间间隔)为统计依据；
static int handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;
	printf("t1:%lu  t2:%lu  delay:%lu\n",e->t1,e->t2,e->delay);

	int dly=(int)(e->delay),i=0;
	while (dly > 1){
		dly /= 2;
		i ++;
	}
	count[i]++;//记录时间间隔次数;
	return 0;
}
static int print_hstgram(int i,int max,int per_len)
{
	int cnt=count[i];
	if(per_len==1){
		while(cnt>0){//打印
			printf("*");
			cnt--;
		}
	}
	while(cnt-per_len>=0){//打印
		printf("*");
		cnt-=per_len;
	}
	printf("\n");
	return per_len;
}
double pow(int n,int k)//实现pow函数
{
	if (k > 0)
		return n * pow(n, k - 1);
	else if (k == 0)
		return 1;
	else
		return 1.0 / pow(n, -k);
}
static void histogram()
{
	int log10[15]={0},max=0,per_len=1;
	for(int i=0;i<10;i++){//log10(count[i]);
		int tmp=count[i],cnt=0;
		while (tmp >= 10){
			tmp /= 10;
			cnt ++;//幂次
		}
		log10[cnt]++;
	}

	for(int i=0;i<10;i++){//找log10里的最大值；
		if(max<log10[i])
			max=i;
	}

	while(max>0){//pow(10,max);
		per_len *=10 ;
		max--;
	}

	time_t now = time(NULL);// 获取当前时间
	struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
	printf("\nTime : %02d:%02d:%02d \n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
	printf("%-24s \t%-12s \t%-12s \n","cs_delay","Count","Distribution");
	printf("%d\t=>\t%-8d \t%-12d \t|",0,1,count[0]);
	print_hstgram(0,max,per_len);
	printf("%d\t=>\t%-8d \t%-12d \t|",2,3,count[1]);
	print_hstgram(1,max,per_len);
	for(int i=2;i<20;i++){
		printf("%d\t=>\t%-8d \t%-12d \t|",(int)pow(2,i),(int)pow(2,(i+1))-1,count[i]);
		print_hstgram(i,max,per_len);
	}
	printf("per_len = %d\n",per_len);
}


/*-----------------------------------------------------------------------------------------------------*/
/*                         libbpf_sar处理函数                                                           */
/*-----------------------------------------------------------------------------------------------------*/
// 根据符号名称从/proc/kallsyms文件中搜索对应符号地址
u64 find_ksym(const char* target_symbol) {
    FILE *file = fopen("/proc/kallsyms", "r");
    if (file == NULL) {
        perror("Failed to open /proc/kallsyms");
        return 1;
    }

    char symbol_name[99];
    u64 symbol_address = 0;

    while (fscanf(file, "%llx %*c %s\n", &symbol_address, symbol_name) != EOF) {
        if (strcmp(symbol_name, target_symbol) == 0) {
            break;
        }
    }

    fclose(file);

    return symbol_address;
}
/*libbpf_sar处理函数*/
static int print_all()
{

	/*proc:*/
	int key_proc = 1;// 设置要查找的键值为0
	int err_proc, fd_proc = bpf_map__fd(skel->maps.countMap);// 获取映射文件描述符
	u64 total_forks;// 用于存储从映射中查找到的值
	err_proc = bpf_map_lookup_elem(fd_proc, &key_proc, &total_forks); // 从映射中查找键为1的值
	if (err_proc < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of total_forks: %d\n", err_proc);
		return -1;
	}
	u64 __proc;
	__proc = total_forks - proc;//计算差值;
	proc = total_forks;

	/*cswch:*/
	int key_cswch = 0;// 设置要查找的键值为1
	int err_cswch, fd_cswch = bpf_map__fd(skel->maps.countMap);// 获取映射文件描述符
	u64 sched_total;// 用于存储从映射中查找到的值
	err_cswch = bpf_map_lookup_elem(fd_cswch, &key_cswch, &sched_total); // 从映射中查找键为1的值
	if (err_cswch < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of sched_total: %d\n", err_cswch);
		return -1;
	}
	u64 __sched;
	__sched = sched_total - sched;//计算差值;
	sched = sched_total;

	// /*runqlen:*/ 
	// int key_runqlen = 0;// 设置要查找的键值为0
	// int err_runqlen, fd_runqlen = bpf_map__fd(skel->maps.runqlen);// 获取映射文件描述符
	// int runqlen;// 用于存储从映射中查找到的值
	// err_runqlen = bpf_map_lookup_elem(fd_runqlen, &key_runqlen, &runqlen); // 从映射中查找键为1的值
	// if (err_runqlen < 0) {//没找到
	// 	fprintf(stderr, "failed to lookup infos of runqlen: %d\n", err_runqlen);
	// 	return -1;
	// }

	/*irqtime:*/
	int key_irqtime = 0;// 设置要查找的键值为0
	int err_irqtime, fd_irqtime = bpf_map__fd(skel->maps.irq_Last_time);// 获取映射文件描述符
	u64 __irqtime;// 用于存储从映射中查找到的值
    __irqtime = irqtime;
	err_irqtime = bpf_map_lookup_elem(fd_irqtime, &key_irqtime, &irqtime); // 从映射中查找键为1的值
	if (err_irqtime < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of irqtime: %d\n", err_irqtime);
		return -1;
	}
    u64 dtairqtime = (irqtime - __irqtime);

	/*softirq:*/
	int key_softirq = 0;// 设置要查找的键值为0
	int err_softirq, fd_softirq = bpf_map__fd(skel->maps.softirqLastTime);// 获取映射文件描述符
	u64 __softirq;// 用于存储从映射中查找到的值
    __softirq = softirq;
	err_softirq = bpf_map_lookup_elem(fd_softirq, &key_softirq, &softirq); // 从映射中查找键为1的值
	if (err_softirq < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of softirq: %d\n", err_softirq);
		return -1;
	}
    u64 dtasoftirq = (softirq - __softirq);

	/*idle*/
	int key_idle = 0;// 设置要查找的键值为0
	int err_idle, fd_idle = bpf_map__fd(skel->maps.idleLastTime);// 获取映射文件描述符
	u64 __idle;// 用于存储从映射中查找到的值
    __idle = idle;
	err_idle = bpf_map_lookup_elem(fd_idle, &key_idle, &idle); // 从映射中查找键为1的值
	if (err_idle < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of idle: %d\n", err_idle);
		return -1;
	}
    u64 dtaidle = (idle - __idle);	

	/*kthread*/
	int key_kthread = 0;
	int err_kthread, fd_kthread = bpf_map__fd(skel->maps.kt_LastTime);
	unsigned long  _ktTime=0; 
	_ktTime = ktTime;
	err_kthread = bpf_map_lookup_elem(fd_kthread, &key_kthread,&ktTime);
	if (err_kthread < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err_kthread);
		return -1;
	}
	unsigned long dtaKT = ktTime -_ktTime;

	/*Uthread*/
	int key_uthread = 0;
	int err_uthread, fd_uthread = bpf_map__fd(skel->maps.ut_LastTime);
	unsigned long  _utTime=0; 
	_utTime = utTime;
	err_uthread = bpf_map_lookup_elem(fd_uthread, &key_uthread,&utTime);
	if (err_uthread < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err_uthread);
		return -1;
	}
	unsigned long dtaUT = utTime -_utTime;

	if(env.enable_proc){
		//判断打印：
		time_t now = time(NULL);// 获取当前时间
		struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
		printf("%02d:%02d:%02d %8llu %8llu %8llu %8llu  %8llu %10lu %13lu\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec,__proc,__sched,dtairqtime/1000,dtasoftirq/1000,dtaidle/1000000,dtaKT/1000,dtaUT/1000);
	}
	else{
		env.enable_proc = true;
	}

    return 0;
}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;//用于存储错误码
	const char* symbol_name = "total_forks";

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);	

	/* 更干净地处理Ctrl-C
	   SIGINT：由Interrupt Key产生，通常是CTRL+C或者DELETE。发送给所有ForeGround Group的进程
       SIGTERM：请求中止进程，kill命令发送
	*/
	signal(SIGINT, sig_handler);		//注册一个信号处理函数 sig_handler，用于处理 Ctrl-C 信号（SIGINT）
	signal(SIGTERM, sig_handler);

	/* 打开BPF应用程序 */
	skel = cpu_watcher_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->forks_addr = (u64)find_ksym(symbol_name);

	/* 加载并验证BPF程序 */
	err = cpu_watcher_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	/* 附加跟踪点处理程序 */
	err = cpu_watcher_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	printf("Tracing for Data's... Ctrl-C to end\n");

    // rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), print_all, NULL, NULL);
	// if (!rb) {
	// 	err = -1;
	// 	fprintf(stderr, "Failed to create ring buffer\n");
	// 	goto cleanup;
	// }

	if(env.libbpf_sar){
		//printf("  time    proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms  BpfCnt\n");
		//printf("  time   softirq\n");
		printf("  time    proc/s  cswch/s  irqTime/us  softirq/us  idle/ms  kthread/us uthread/ms\n");
	}
	else if(env.cs_delay){
		/* 设置环形缓冲区轮询 */
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto cleanup;
		}
	}
	/* 处理事件 */
	while (!exiting) {
		sleep(1);
		if(env.libbpf_sar){
			err = print_all();
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
		}
        else if(env.cs_delay){
			err = ring_buffer__poll(rb, 1000 /* timeout, s */);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
			/*打印直方图*/
			histogram();
		}
		else {
			printf("正在开发中, -c打印cs_delay, -s打印libbpf_sar\n");
			break;
		}
	}
	
/* 卸载BPF程序 */
cleanup:
    /* Clean up */
	if(env.cs_delay) ring_buffer__free(rb);//释放环形缓冲区
	cpu_watcher_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}
