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
// author: albert_xuu@163.com zhangxy1016304@163.com zhangziheng0525@163.com


#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include <sys/select.h>
#include <unistd.h> 
#include <stdlib.h>
#include <string.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "cpu_watcher.h"
#include "sar.skel.h"
#include "cs_delay.skel.h"
#include "sc_delay.skel.h"
#include "preempt.skel.h"
#include "schedule_delay.skel.h"
#include "mq_delay.skel.h"

typedef long long unsigned int u64;
typedef unsigned int u32;
#define MAX_BUF 512

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};
struct msg_msg {
	struct list_head m_list;
	long int m_type;
	size_t m_ts;
	struct msg_msgseg *next;
	void *security;
};

static struct env {
    int time;
	int period;
	bool percent;
    bool enable_proc;
    bool SAR;
    bool CS_DELAY;
    bool SYSCALL_DELAY;
    bool PREEMPT;
    bool SCHEDULE_DELAY;
	bool MQ_DELAY;
    int freq;
} env = {
    .time = 0,
	.period = 1,
	.percent = false,
    .enable_proc = false,
    .SAR = false,
    .CS_DELAY = false,
    .SYSCALL_DELAY = false,
    .PREEMPT = false,
    .SCHEDULE_DELAY = false,
	.MQ_DELAY = false,
    .freq = 99
};


struct cs_delay_bpf *cs_skel;
struct sar_bpf *sar_skel;
struct sc_delay_bpf *sc_skel;
struct preempt_bpf *preempt_skel;
struct schedule_delay_bpf *sd_skel;
struct mq_delay_bpf *mq_skel;

u64 softirq = 0;
u64 irqtime = 0;
u64 idle = 0;
u64 sched = 0;
u64 proc = 0;
unsigned long ktTime = 0;
unsigned long utTime = 0;
u64 tick_user = 0;


int sc_sum_time = 0 ;
int sc_max_time = 0 ;
int sc_min_time = SYSCALL_MIN_TIME ;
int sys_call_count = 0;
bool ifprint = 0;


int preempt_count = 0 ;
int sum_preemptTime = 0 ;
int preempt_start_print = 0 ;

/*设置传参*/
const char argp_program_doc[] ="cpu wacher is in use ....\n";
static const struct argp_option opts[] = {
	{ "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{ "period", 'i', "INTERVAL", 0, "Period interval in seconds" },
	{"percent",'P',0,0,"format data as percentages"},
	{"libbpf_sar", 's',	0,0,"print sar_info (the data of cpu)"},
	{"cs_delay", 'c',	0,0,"print cs_delay (the data of cpu)"},
	{"syscall_delay", 'S',	0,0,"print syscall_delay (the data of syscall)"},
	{"preempt_time", 'p',	0,0,"print preempt_time (the data of preempt_schedule)"},
	{"schedule_delay", 'd',	0,0,"print schedule_delay (the data of cpu)"},
	{"mq_delay", 'm',	0,0,"print mq_delay(the data of proc)"},
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
		case 'i':
			env.period = strtol(arg, NULL, 10);
			break;
		case 'P':
			env.percent = true;
			break;
		case 's':
			env.SAR = true;
			break;
		case 'c':
			env.CS_DELAY = true;
			break;		
		case 'S':
			env.SYSCALL_DELAY = true;
			break;			
		case 'p':
			env.PREEMPT = true;
			break;
		case 'd':
			env.SCHEDULE_DELAY = true;
			break;
		case 'm':
			env.MQ_DELAY = true;
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
	int nprocs = get_nprocs();
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

	 /*runqlen:*/ 
	int key_runqlen = 0;
	int err_runqlen, fd_runqlen = bpf_map__fd(sar_skel->maps.runqlen);
	int runqlen;
	err_runqlen = bpf_map_lookup_elem(fd_runqlen, &key_runqlen, &runqlen);
	if (err_runqlen < 0) {
		fprintf(stderr, "failed to lookup infos of runqlen: %d\n", err_runqlen);
		return -1;
	}

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
	int key_sys = 0;
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
		if (env.percent == true){
			printf("%02d:%02d:%02d %8llu %8llu %6d  ",localTime->tm_hour, localTime->tm_min, localTime->tm_sec,__proc, __sched, runqlen);
			// 大于百分之60的标红输出
			double values[7] = {
				(double)dtairqtime / 10000000 / nprocs / env.period,
				(double)dtasoftirq / 10000000 / nprocs / env.period,
				(double)dtaidle / 10000000 / nprocs / env.period,
				(double)dtaKT / 10000000 / nprocs / env.period,
				(double)dtaSysc / 10000000 / nprocs / env.period,
				(double)dtaUTRaw / 10000000 / nprocs / env.period,
				(double)dtaSys / 10000000 / nprocs / env.period
			};
			for (int i = 0; i < 7; i++) {
				if (values[i] > 60.0) {
					printf("\033[1;31m");  // 设置为红色
				}
				printf("%10.2f ", values[i]);
				printf("\033[0m");  // 重置为默认颜色
			}
			printf("\n");
		}else{printf("%02d:%02d:%02d %8llu %8llu %6d %8llu %10llu  %8llu  %10lu  %8llu %8llu %8llu\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
				__proc,__sched,runqlen,dtairqtime/1000,dtasoftirq/1000,dtaidle/1000000,
				dtaKT/1000,dtaSysc / 1000000,dtaUTRaw/1000000,dtaSys / 1000000);}
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
	printf("t1:%llu  t2:%llu  delay:%llu\n",e->t1,e->t2,e->delay);
	int dly=(int)(e->delay),i=0;
	while (dly > 1){
		dly /= 2;
		i ++;
	}
	count[i]++;
	return 0;
}
static int print_hstgram(int i,int max,int per_len)
{
	int cnt=count[i];
	if(per_len==1){
		while(cnt>0){
			printf("*");
			cnt--;
		}
	}
	while(cnt-per_len>=0){
		printf("*");
		cnt-=per_len;
	}
	printf("\n");
	return per_len;
}
double my_pow(int n,int k)//实现pow函数
{
	if (k > 0)
		return n * my_pow(n, k - 1);
	else if (k == 0)
		return 1;
	else
		return 1.0 / my_pow(n, -k);
}
static void histogram()
{
	int log10[15]={0},max=0,per_len=1;
	for(int i=0;i<10;i++){
		int tmp=count[i],cnt=0;
		while (tmp >= 10){
			tmp /= 10;
			cnt ++;
		}
		log10[cnt]++;
	}

	for(int i=0;i<10;i++){//找log10里的最大值；
		if(max<log10[i])
			max=i;
	}

	while(max>0){
		per_len *=10 ;
		max--;
	}

	time_t now = time(NULL);
	struct tm *localTime = localtime(&now);
	printf("\nTime : %02d:%02d:%02d \n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
	printf("%-24s \t%-12s \t%-12s \n","cs_delay","Count","Distribution");
	printf("%d\t=>\t%-8d \t%-12d \t|",0,1,count[0]);
	print_hstgram(0,max,per_len);
	printf("%d\t=>\t%-8d \t%-12d \t|",2,3,count[1]);
	print_hstgram(1,max,per_len);
	for(int i=2;i<20;i++){
		printf("%d\t=>\t%-8d \t%-12d \t|",(int)my_pow(2,i),(int)my_pow(2,(i+1))-1,count[i]);
		print_hstgram(i,max,per_len);
	}
	printf("per_len = %d\n",per_len);
}


static int syscall_delay_print(void *ctx, void *data,unsigned long data_sz)
{

	const struct syscall_events *e = data;
	printf("pid: %-8u comm: %-10s syscall_id: %-8lld delay: %-8lld\n",
		e->pid,e->comm,e->syscall_id,e->delay);
	return 0;
}

//抢占时间输出
static int preempt_print(void *ctx, void *data, unsigned long data_sz)
{
    const struct preempt_event *e = data;
    printf("%-16s %-7d %-7d %-11llu\n", e->comm, e->prev_pid, e->next_pid, e->duration);
    preempt_count++;
    sum_preemptTime += e->duration;
    return 0;
}

char* get_process_name_by_pid(int pid) {
    static char buf[MAX_BUF];
    char command[MAX_BUF];
    snprintf(command, sizeof(command), "cat /proc/%d/status | grep Name", pid);
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        return NULL;
    }
    char* name = NULL;
    while (fgets(buf, sizeof(buf), fp)) {
        if (strncmp(buf, "Name:", 5) == 0) {
            name = strdup(buf + 6); 
            break;
        }
    }
    pclose(fp);
	if (name != NULL) {
        size_t len = strlen(name);
        if (len > 0 && name[len - 1] == '\n') {
            name[len - 1] = '\0';
        }
    }
    return name;
}

static int schedule_print(struct bpf_map *sys_fd)
{
    int key = 0;
    struct sum_schedule info;
    int err, fd = bpf_map__fd(sys_fd);
    time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    int hour = localTime->tm_hour;
    int min = localTime->tm_min;
    int sec = localTime->tm_sec;
    unsigned long long avg_delay; 
    err = bpf_map_lookup_elem(fd, &key, &info);
    if (err < 0) {
        fprintf(stderr, "failed to lookup infos: %d\n", err);
        return -1;
    }
    avg_delay = info.sum_delay / info.sum_count;
	if(!ifprint){
		ifprint=1;
	}else{
		char* proc_name_max = get_process_name_by_pid(info.pid_max);
		char* proc_name_min = get_process_name_by_pid(info.pid_min);
		printf("%02d:%02d:%02d  %-15lf %-15lf  %10s %15lf  %15s\n",
           hour, min, sec, avg_delay / 1000.0, info.max_delay / 1000.0,proc_name_max,info.min_delay / 1000.0,proc_name_min);
		if (proc_name_max != NULL) {
    		free(proc_name_max);
		}
		if (proc_name_min != NULL) {
			free(proc_name_min);		
		}
	}
    return 0;
}

static int mq_event(void *ctx, void *data,unsigned long data_sz)
{
	time_t now = time(NULL);// 获取当前时间
	struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
	const struct mq_events *e = data;
	float send_delay,rcv_delay,delay;
	if(!e->send_enter_time || !e->send_exit_time || !e->rcv_enter_time || !e->rcv_exit_time) {
		printf("erro!\n");
		return 0;
	}
	send_delay = (e->send_exit_time - e->send_enter_time)/1000000.0;
	rcv_delay = (e->rcv_exit_time - e->rcv_enter_time)/1000000.0;	
	if(e->send_enter_time < e->rcv_enter_time){
		delay = (e->rcv_exit_time - e->send_enter_time)/1000000.0;
	}else{
		delay = (e->rcv_exit_time - e->send_enter_time)/1000000.0 + send_delay + rcv_delay;		
	}
	printf("%02d:%02d:%02d   %-8u %-8u %-8u \t%-16llu %-16llu %-16llu %-16llu\t%-15.5f %-15.5f %-15.5f\n",
		localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
		e->mqdes,e->send_pid,e->rcv_pid,
		e->send_enter_time,e->send_exit_time,e->rcv_enter_time,e->rcv_exit_time,
		send_delay,rcv_delay,delay);

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
	}else if (env.PREEMPT) {
		preempt_skel = preempt_bpf__open();
		if (!preempt_skel) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		err = preempt_bpf__load(preempt_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto preempt_cleanup;
		}

		err = preempt_bpf__attach(preempt_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto preempt_cleanup;
		}

		rb = ring_buffer__new(bpf_map__fd(preempt_skel->maps.rb), preempt_print, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto preempt_cleanup;
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
	}else if(env.SCHEDULE_DELAY){
		sd_skel = schedule_delay_bpf__open();
		if (!sd_skel) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		err = schedule_delay_bpf__load(sd_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto schedule_cleanup;
		}
		err = schedule_delay_bpf__attach(sd_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto schedule_cleanup;
		}
		printf("%-8s %s\n",  "  TIME ", "avg_delay/μs     max_delay/μs    max_proc_name    min_delay/μs   min_proc_name");
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
		if (env.percent){
			printf("  time       proc/s  cswch/s  runqlen  irqTime/%%  softirq/%%  idle/%%    kthread/%%    sysc/%%     utime/%%     sys/%% \n");
		}else{printf("  time    proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms \n");}
	}else if(env.MQ_DELAY){
		/* Load and verify BPF application */
		mq_skel = mq_delay_bpf__open();
		if (!mq_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		/* Load & verify BPF programs */
		err = mq_delay_bpf__load(mq_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto mq_delay_cleanup;
		}
		/* Attach tracepoints */
		err = mq_delay_bpf__attach(mq_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto mq_delay_cleanup;
		}
		printf("%-8s   %-8s %-8s %-8s \t%-16s %-16s %-16s %-16s\t%-15s %-15s %-15s\n","Time","Mqdes","SND_PID","RCV_PID","SND_Enter","SND_EXit","RCV_Enter","RCV_EXit","SND_Delay/ms","RCV_Delay/ms","Delay/ms");		
		rb = ring_buffer__new(bpf_map__fd(mq_skel->maps.rb), mq_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto mq_delay_cleanup;
		}
	}
	while (!exiting) {
		if(env.SAR){
			sleep(env.period);
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
			printf("\n\nTime: %02d:%02d:%02d\n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
			printf("----------------------------------------------------------------------------------------------------------\n");
			sleep(1);			
		}
		else if (env.PREEMPT) {
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling perf buffer: %d\n", err);
				break;
			}
			time_t now = time(NULL);
			struct tm *localTime = localtime(&now);
			if (!preempt_start_print) {
				preempt_start_print = 1;
			} else {
				printf("----------------------------------------------------------------------------------------------------------\n");
				printf("\nAverage_preempt_Time: %8d ns\n", sum_preemptTime / preempt_count);
			}
			printf("\nTime: %02d:%02d:%02d\n", localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
			printf("%-12s %-8s %-8s %11s\n", "COMM", "prev_pid", "next_pid", "duration_ns");
			preempt_count = 0;
			sum_preemptTime = 0;
			sleep(2);
		}
		else if (env.SCHEDULE_DELAY){
			err = schedule_print(sd_skel->maps.sys_schedule);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				break;
			}
			sleep(1);
		}
        else if(env.MQ_DELAY){
			err = ring_buffer__poll(rb, 1000 /* timeout, s */);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
		}
		else {
			printf("正在开发中......\n-c	打印cs_delay:\t对内核函数schedule()的执行时长进行测试;\n-s	sar工具;\n-y	打印sc_delay:\t系统调用运行延迟进行检测; \n-p	打印preempt_time:\t对抢占调度时间输出;\n");
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

preempt_cleanup:
	ring_buffer__free(rb);
	preempt_bpf__destroy(preempt_skel);
	return err < 0 ? -err : 0;

schedule_cleanup:
	schedule_delay_bpf__destroy(sd_skel);
	return err < 0 ? -err : 0;

mq_delay_cleanup:
	ring_buffer__free(rb);
	mq_delay_bpf__destroy(mq_skel);
	return err < 0 ? -err : 0;
}
