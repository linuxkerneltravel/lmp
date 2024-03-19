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


#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/select.h>
#include <unistd.h> 
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "cpu_watcher/include/cpu_watcher.h"

#include "process/cpu_watcher/sar.skel.h"
#include "process/cpu_watcher/cs_delay.skel.h"
#include "process/cpu_watcher/sc_delay.skel.h"

typedef long long unsigned int u64;
typedef unsigned int u32;
static struct env {
	int time;
	bool enable_proc;
	bool SAR;
	bool CS_DELAY;
	bool SYSCALL_DELAY;
	int freq;
} env = {
	.time = 0,
	.enable_proc = false,
	.SAR = false,
	.CS_DELAY = false,
	.SYSCALL_DELAY = false,
	.freq = 99,
};

struct cs_delay_bpf *cs_skel;
struct sar_bpf *sar_skel;
struct sc_delay_bpf *sc_skel;

u64 softirq = 0;//初始化softirq;
u64 irqtime = 0;//初始化irq;
u64 idle = 0;//初始化idle;s
u64 sched = 0;
u64 proc = 0;
unsigned long ktTime = 0;
unsigned long utTime = 0;
u64 tick_user = 0;//初始化sys;

int sc_sum_time = 0 ;
int sc_max_time = 0 ;
int sc_min_time = SYSCALL_MIN_TIME ;
int sys_call_count = 0;


/*设置传参*/
const char argp_program_doc[] ="cpu wacher is in use ....\n";
static const struct argp_option opts[] = {
	{ "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{"libbpf_sar", 's',	0,0,"print sar_info (the data of cpu)"},
	{"cs_delay", 'c',	0,0,"print cs_delay (the data of cpu)"},
	{"syscall_delay", 'y',	0,0,"print syscall_delay (the data of syscall)"},
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
			env.SAR = true;
			break;
		case 'c':
			env.CS_DELAY = true;
			break;		
		case 'y':
			env.SYSCALL_DELAY = true;
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



static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting=false;
bool syscall_start_print = false;

static void sig_handler(int sig)
{
	exiting = true;
}

/*perf_event*/
static int nr_cpus;
static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 99,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
}


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

static int print_all()
{
	/*proc:*/
	int key_proc = 1;
	int err_proc, fd_proc = bpf_map__fd(sar_skel->maps.countMap);
	u64 total_forks;
	err_proc = bpf_map_lookup_elem(fd_proc, &key_proc, &total_forks); 
	if (err_proc < 0) {
		fprintf(stderr, "failed to lookup infos of total_forks: %d\n", err_proc);
		return -1;
	}
	u64 __proc;
	__proc = total_forks - proc;
	proc = total_forks;
	/*cswch:*/
	int key_cswch = 0;
	int err_cswch, fd_cswch = bpf_map__fd(sar_skel->maps.countMap);
	u64 sched_total;
	err_cswch = bpf_map_lookup_elem(fd_cswch, &key_cswch, &sched_total);
	if (err_cswch < 0) {
		fprintf(stderr, "failed to lookup infos of sched_total: %d\n", err_cswch);
		return -1;
	}
	u64 __sched;
	__sched = sched_total - sched;
	sched = sched_total;

	// /*runqlen:*/ 
	// int key_runqlen = 0;// 设置要查找的键值为0
	// int err_runqlen, fd_runqlen = bpf_map__fd(sar_skel->maps.runqlen);// 获取映射文件描述符
	// int runqlen;// 用于存储从映射中查找到的值
	// err_runqlen = bpf_map_lookup_elem(fd_runqlen, &key_runqlen, &runqlen); // 从映射中查找键为1的值
	// if (err_runqlen < 0) {//没找到
	// 	fprintf(stderr, "failed to lookup infos of runqlen: %d\n", err_runqlen);
	// 	return -1;
	// }

	/*irqtime:*/
	int key_irqtime = 0;
	int err_irqtime, fd_irqtime = bpf_map__fd(sar_skel->maps.irq_Last_time);
	u64 __irqtime;
    __irqtime = irqtime;
	err_irqtime = bpf_map_lookup_elem(fd_irqtime, &key_irqtime, &irqtime);
	if (err_irqtime < 0) {
		fprintf(stderr, "failed to lookup infos of irqtime: %d\n", err_irqtime);
		return -1;
	}
    u64 dtairqtime = (irqtime - __irqtime);

	/*softirq:*/
	int key_softirq = 0;
	int err_softirq, fd_softirq = bpf_map__fd(sar_skel->maps.softirqLastTime);
	u64 __softirq;
    __softirq = softirq;
	err_softirq = bpf_map_lookup_elem(fd_softirq, &key_softirq, &softirq); 
	if (err_softirq < 0) {
		fprintf(stderr, "failed to lookup infos of softirq: %d\n", err_softirq);
		return -1;
	}
    u64 dtasoftirq = (softirq - __softirq);

	/*idle*/
	int key_idle = 0;
	int err_idle, fd_idle = bpf_map__fd(sar_skel->maps.idleLastTime);
	u64 __idle;
    __idle = idle;
	err_idle = bpf_map_lookup_elem(fd_idle, &key_idle, &idle);
	if (err_idle < 0) {
		fprintf(stderr, "failed to lookup infos of idle: %d\n", err_idle);
		return -1;
	}
    u64 dtaidle = (idle - __idle);	

	/*kthread*/
	int key_kthread = 0;
	int err_kthread, fd_kthread = bpf_map__fd(sar_skel->maps.kt_LastTime);
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
	int err_uthread, fd_uthread = bpf_map__fd(sar_skel->maps.ut_LastTime);
	unsigned long  _utTime=0; 
	_utTime = utTime;
	err_uthread = bpf_map_lookup_elem(fd_uthread, &key_uthread,&utTime);
	if (err_uthread < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err_uthread);
		return -1;
	}
	unsigned long dtaUT = utTime -_utTime;

	/*sys*/
	int key_sys = 0,next_key;
	int err_sys, fd_sys = bpf_map__fd(sar_skel->maps.tick_user);
	u64 __tick_user =0 ;// 用于存储从映射中查找到的值
	__tick_user = tick_user;
	//tick_user = 0;
	err_sys = bpf_map_lookup_elem(fd_sys, &key_sys, &tick_user);
	if (err_sys < 0) {
		fprintf(stderr, "failed to lookup infos of sys: %d\n", err_sys);
		return -1;
	}
	u64 dtaTickUser = tick_user - __tick_user;
	u64 dtaUTRaw = dtaTickUser/(99.0000) * 1000000000; 
	u64 dtaSysc = abs(dtaUT - dtaUTRaw);
	u64 dtaSys = dtaKT + dtaSysc ;

	if(env.enable_proc){
		time_t now = time(NULL);
		struct tm *localTime = localtime(&now);
		printf("%02d:%02d:%02d %8llu %8llu %8llu %10llu  %8llu  %8llu  %8llu %8lu %8lu\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
				__proc,__sched,dtairqtime/1000,dtasoftirq/1000,dtaidle/1000000,
				dtaKT/1000,dtaSysc / 1000000,dtaUTRaw/1000000,dtaSys / 1000000);
	}
	else{
		env.enable_proc = true;
	}

    return 0;
}

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


static void max_print(){

	int sc_average_time = sc_sum_time/sys_call_count;
	printf("Average_Syscall_Time: %8d ms\n",sc_average_time);
	printf("MAX_Syscall_Time: %8d ms\n",sc_max_time);
	printf("MIN_Syscall_Time: %8d ms\n",sc_min_time);
}
static int syscall_delay_print(void *ctx, void *data,unsigned long data_sz)
{

	const struct event2 *e = data;
	printf("|COMM:  %-15s |pid: %-8lu  |start_time: %-10lu  |exit_time: %-10lu  |delay: %-8lu|\n",e->comm,e->pid,e->start_time,e->exit_time,e->delay);
	sc_sum_time += e->delay;
	if(sc_max_time < e->delay){
		sc_max_time = e->delay;
	}
	else if(sc_min_time > e->delay){
		sc_min_time = e->delay;
	}
	sys_call_count ++;
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	const char* symbol_name = "total_forks";
	struct bpf_link *links[MAX_CPU_NR] = {};
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}


	if (env.CS_DELAY)
	{
		/* Load and verify BPF application */
		cs_skel = cs_delay_bpf__open();
		if (!cs_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		/* Load & verify BPF programs */
		err = cs_delay_bpf__load(cs_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto cs_delay_cleanup;
		}
		/* Attach tracepoints */
		err = cs_delay_bpf__attach(cs_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto cs_delay_cleanup;
		}
		rb = ring_buffer__new(bpf_map__fd(cs_skel->maps.rb), handle_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto cs_delay_cleanup;
		}
	}else if (env.SYSCALL_DELAY){
		/* Load and verify BPF application */
		sc_skel = sc_delay_bpf__open();
		if (!sc_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		/* Load & verify BPF programs */
		err = sc_delay_bpf__load(sc_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto sc_delay_cleanup;
		}
		/* Attach tracepoints */
		err = sc_delay_bpf__attach(sc_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto sc_delay_cleanup;
		}
		rb = ring_buffer__new(bpf_map__fd(sc_skel->maps.rb), syscall_delay_print, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto sc_delay_cleanup;		
		}
	}else if (env.SAR){
		/* Load and verify BPF application */
		sar_skel = sar_bpf__open();
		if (!sar_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		sar_skel->rodata->forks_addr = (u64)find_ksym(symbol_name);
		/* Load & verify BPF programs */
		err = sar_bpf__load(sar_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto sar_cleanup;
		}

		/*perf_event加载*/
		err = open_and_attach_perf_event(env.freq, sar_skel->progs.tick_update, links);
		if (err)
			goto sar_cleanup;

		err = sar_bpf__attach(sar_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto sar_cleanup;
		}
		//printf("  time    proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms  BpfCnt\n");
		printf("  time    proc/s  cswch/s  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms\n");
	}
	while (!exiting) {
		if(env.SAR){
			sleep(1);
			err = print_all();
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
		}
        else if(env.CS_DELAY){
			sleep(1);
			err = ring_buffer__poll(rb, 1000 /* timeout, s */);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
			histogram();
		}
		else if(env.SYSCALL_DELAY){
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);		//ring_buffer__poll(),轮询打开ringbuf缓冲区。如果有事件，handle_event函数会执行	
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling perf buffer: %d\n", err);
				break;
			}
			time_t now = time(NULL);// 获取当前时间
			struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
			if(!syscall_start_print){
				syscall_start_print=1;
			}else{
				printf("----------------------------------------------------------------------------------------------------------\n");
				max_print();
			}
			printf("\n\nTime: %02d:%02d:%02d\n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
			printf("----------------------------------------------------------------------------------------------------------\n");
			sc_sum_time = 0 , sc_max_time = 0 ,sc_min_time = SYSCALL_MIN_TIME, sys_call_count = 0;
			sleep(3);			
		}
		else {
			printf("正在开发中......\n-c	打印cs_delay:\t对内核函数schedule()的执行时长进行测试;\n-s	sar工具;\n-y	打印sc_delay:\t系统调用运行延迟进行检测; \n");
			break;
		}
	}

cs_delay_cleanup:
	ring_buffer__free(rb);
	cs_delay_bpf__destroy(cs_skel);
	return err < 0 ? -err : 0;

sar_cleanup:
	sar_bpf__destroy(sar_skel);
	return err < 0 ? -err : 0;

sc_delay_cleanup:
	ring_buffer__free(rb);
	sc_delay_bpf__destroy(sc_skel);
	return err < 0 ? -err : 0;
}
