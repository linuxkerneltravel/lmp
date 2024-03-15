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
// user-mode code for the process image

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "proc_image/include/proc_image.h"
#include "proc_image/include/helpers.h"

// #include "process/proc_image/resource_image.skel.h"
#include "process/proc_image/syscall_image.skel.h"
#include "process/proc_image/lock_image.skel.h"
#include "process/proc_image/keytime_image.skel.h"
#include "process/proc_image/schedule_image.skel.h"

static int prev_image = 0;
static volatile bool exiting = false;
static const char object[] = "/usr/lib/x86_64-linux-gnu/libc.so.6";
static struct env {
    int pid;
	int tgid;
	int ignore_tgid;
    int cpu_id;
    int time;
	bool enable_myproc;
	bool output_resourse;
	bool output_schedule;
	bool create_thread;
	bool exit_thread;
    bool enable_resource;
	bool first_rsc;
	int syscalls;
	int first_syscall;
	int second_syscall;
	int third_syscall;
	u64 sum_delay;
	u64 sum_count;
	u64 max_delay;
	bool enable_syscall;
	bool enable_lock;
	bool quote;
	int max_args;
	bool enable_keytime;
	bool enable_schedule;
} env = {
    .pid = -1,
	.tgid = -1,
    .cpu_id = -1,
    .time = 0,
	.enable_myproc = false,
	.output_resourse = false,
	.output_schedule = false,
	.create_thread = false,
	.exit_thread = false,
    .enable_resource = false,
	.first_rsc = true,
	.syscalls = 0,
	.first_syscall = 0,
	.second_syscall = 0,
	.third_syscall = 0,
	.sum_delay = 0,
	.sum_count = 0,
	.max_delay = 0,
	.enable_syscall = false,
	.enable_lock = false,
	.quote = false,
	.max_args = DEFAULT_MAXARGS,
	.enable_keytime = false,
	.enable_schedule = false,
};

static struct timespec prevtime;
static struct timespec currentime;

char *lock_status[] = {"", "mutex_req", "mutex_lock", "mutex_unlock",
						   "rdlock_req", "rdlock_lock", "rdlock_unlock",
						   "wrlock_req", "wrlock_lock", "wrlock_unlock"};

char *keytime_type[] = {"", "exec_enter", "exec_exit", 
						    "exit", 
						    "forkP_enter", "forkP_exit",
						    "vforkP_enter", "vforkP_exit",
						    "createT_enter", "createT_exit"};

u32 syscalls[NR_syscalls] = {};

const char argp_program_doc[] ="Trace process to get process image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "tgid", 'P', "TGID", 0, "Thread group to trace" },
    { "cpuid", 'c', "CPUID", 0, "Set For Tracing  per-CPU Process(other processes don't need to set this parameter)" },
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{ "myproc", 'm', NULL, 0, "Trace the process of the tool itself (not tracked by default)" },
	{ "all", 'a', NULL, 0, "Start all functions(but not track tool progress)" },
    { "resource", 'r', NULL, 0, "Collects resource usage information about processes" },
	{ "syscall", 's', "SYSCALLS", 0, "Collects syscall sequence (1~50) information about processes" },
	{ "lock", 'l', NULL, 0, "Collects lock information about processes" },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments" },
	{ "keytime", 'k', NULL, 0, "Collects keytime information about processes" },
	{ "schedule", 'S', NULL, 0, "Collects schedule information about processes (trace tool process)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;
	long tgid;
	long cpu_id;
	long syscalls;
	switch (key) {
		case 'p':
				errno = 0;
				pid = strtol(arg, NULL, 10);
				if (errno || pid < 0) {
					warn("Invalid PID: %s\n", arg);
					// 调用argp_usage函数，用于打印用法信息并退出程序
					argp_usage(state);
				}
				env.pid = pid;
				break;
        case 'P':
				errno = 0;
				tgid = strtol(arg, NULL, 10);
				if (errno || tgid < 0) {
					warn("Invalid TGID: %s\n", arg);
					// 调用argp_usage函数，用于打印用法信息并退出程序
					argp_usage(state);
				}
				env.tgid = tgid;
				break;
		case 'c':
				cpu_id = strtol(arg, NULL, 10);
				if(cpu_id < 0){
					warn("Invalid CPUID: %s\n", arg);
					argp_usage(state);
				}
				env.cpu_id = cpu_id;
				break;
		case 't':
				env.time = strtol(arg, NULL, 10);
				if(env.time) alarm(env.time);
				break;
		case 'm':
				env.enable_myproc = true;
				break;
		case 'a':
				env.enable_resource = true;
				env.syscalls = 10;
				env.enable_syscall = true;
				env.enable_lock = true;
				env.enable_keytime = true;
				env.enable_schedule = true;
				break;
        case 'r':
                env.enable_resource = true;
                break;
		case 's':
                syscalls = strtol(arg, NULL, 10);
				if(syscalls<=0 && syscalls>50){
					warn("Invalid SYSCALLS: %s\n", arg);
					argp_usage(state);
				}
				env.syscalls = syscalls;
				env.enable_syscall = true;
                break;
		case 'l':
                env.enable_lock = true;
                break;
		case 'q':
				env.quote = true;
				break;
		case 'k':
				env.enable_keytime = true;
				break;
		case 'S':
				env.enable_schedule = true;
				break;
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
        default:
				return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

static int print_resource(struct bpf_map *map)
{
	struct proc_id lookup_key = {-1}, next_key;
	int err, fd = bpf_map__fd(map);

	if(env.first_rsc){
		env.first_rsc = false;
		goto delete_elem;
	}

	struct total_rsc event;
	float pcpu,pmem;
	double read_rate,write_rate;
	unsigned long memtotal = sysconf(_SC_PHYS_PAGES);
    time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    int hour = localTime->tm_hour;
    int min = localTime->tm_min;
    int sec = localTime->tm_sec;
	long long unsigned int interval;
    
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		if(prev_image != RESOURCE_IMAGE){
			printf("RESOURCE ------------------------------------------------------------------------------------------------\n");
			printf("%-8s  %-6s  %-6s  %-6s  %-6s  %-12s  %-12s\n","TIME","PID","CPU-ID","CPU(%)","MEM(%)","READ(kb/s)","WRITE(kb/s)");
			prev_image = RESOURCE_IMAGE;
		}

		err = bpf_map_lookup_elem(fd, &next_key, &event);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}
		
		clock_gettime(CLOCK_REALTIME, &currentime);
		interval = currentime.tv_nsec-prevtime.tv_nsec+(currentime.tv_sec-prevtime.tv_sec)*1000000000;

		if(interval>0 && memtotal>0 && event.time>0){
			pcpu = (100.0*event.time)/interval;
			pmem = (100.0*event.memused)/memtotal;
			read_rate = (1.0*event.readchar)/1024/((1.0*event.time)/1000000000);            // kb/s
			write_rate = (1.0*event.writechar)/1024/((1.0*event.time)/1000000000);          // kb/s
		}else{
			goto next_elem;
		}
		
		if(pcpu<=100 && pmem<=100){
			printf("%02d:%02d:%02d  %-6d  %-6d  %-6.3f  %-6.3f  %-12.2lf  %-12.2lf\n",
					hour,min,sec,event.pid,event.cpu_id,pcpu,pmem,read_rate,write_rate);
		}

next_elem:
		lookup_key = next_key;
	}

delete_elem:
    lookup_key.pid = -1;	
	lookup_key.cpu_id = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	// 获取当前高精度时间
    clock_gettime(CLOCK_REALTIME, &prevtime);
	env.output_resourse = false;

	return 0;
}

static int print_schedule(struct bpf_map *proc_map,struct bpf_map *target_map,struct bpf_map *tg_map,struct bpf_map *sys_map)
{
	struct proc_id lookup_key = {-1}, next_key;
	int l_key = -1, n_key;
	int err;
	int proc_fd = bpf_map__fd(proc_map);
	int target_fd = bpf_map__fd(target_map);
	int tg_fd = bpf_map__fd(tg_map);
	int sys_fd = bpf_map__fd(sys_map);
	struct schedule_event proc_event;
	struct sum_schedule sys_event;
	time_t now = time(NULL);
	struct tm *localTime = localtime(&now);
    int hour = localTime->tm_hour;
    int min = localTime->tm_min;
    int sec = localTime->tm_sec;
	u64 proc_avg_delay;
	u64 target_avg_delay;
	u64 sys_avg_delay;
	int key = 0;

	if(prev_image != SCHEDULE_IMAGE){
		printf("SCHEDULE ----------------------------------------------------------------------------------------------------------------------\n");
		printf("%-8s  ","TIME");
		if(env.tgid != -1)	printf("%-6s  ","TGID");
		printf("%-6s  %-4s  %s\n","PID","PRIO","| P_AVG_DELAY(ms) S_AVG_DELAY(ms) | P_MAX_DELAY(ms) S_MAX_DELAY(ms) | P_MIN_DELAY(ms) S_MIN_DELAY(ms) |");
		prev_image = SCHEDULE_IMAGE;
	}

	if(env.pid==-1 && env.tgid==-1){
		while (!bpf_map_get_next_key(proc_fd, &lookup_key, &next_key)) {
			err = bpf_map_lookup_elem(proc_fd, &next_key, &proc_event);
			if (err < 0) {
				fprintf(stderr, "failed to lookup infos: %d\n", err);
				return -1;
			}
			proc_avg_delay = proc_event.sum_delay/proc_event.count;

			err = bpf_map_lookup_elem(sys_fd, &key, &sys_event);
			if (err < 0) {
				fprintf(stderr, "failed to lookup infos: %d\n", err);
				return -1;
			}
			sys_avg_delay = sys_event.sum_delay/sys_event.sum_count;

			printf("%02d:%02d:%02d  %-6d  %-4d  | %-15lf %-15lf | %-15lf %-15lf | %-15lf %-15lf |\n",
					hour,min,sec,proc_event.pid,proc_event.prio,proc_avg_delay/1000000.0,sys_avg_delay/1000000.0,
					proc_event.max_delay/1000000.0,sys_event.max_delay/1000000.0,proc_event.min_delay/1000000.0,sys_event.min_delay/1000000.0);
			
			lookup_key = next_key;
		}
	}else if(env.pid!=-1 && env.tgid==-1){
		err = bpf_map_lookup_elem(target_fd, &key, &proc_event);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}

		if(proc_event.count != 0){	
			target_avg_delay = proc_event.sum_delay/proc_event.count;
			
			err = bpf_map_lookup_elem(sys_fd, &key, &sys_event);
			if (err < 0) {
				fprintf(stderr, "failed to lookup infos: %d\n", err);
				return -1;
			}
			sys_avg_delay = sys_event.sum_delay/sys_event.sum_count;

			printf("%02d:%02d:%02d  %-6d  %-4d  | %-15lf %-15lf | %-15lf %-15lf | %-15lf %-15lf |\n",
					hour,min,sec,proc_event.pid,proc_event.prio,target_avg_delay/1000000.0,sys_avg_delay/1000000.0,
					proc_event.max_delay/1000000.0,sys_event.max_delay/1000000.0,proc_event.min_delay/1000000.0,sys_event.min_delay/1000000.0);
		}
	}else if(env.pid==-1 && env.tgid!=-1){
		while (!bpf_map_get_next_key(tg_fd, &l_key, &n_key)) {
			err = bpf_map_lookup_elem(tg_fd, &n_key, &proc_event);
			if (err < 0) {
				fprintf(stderr, "failed to lookup infos: %d\n", err);
				return -1;
			}
			proc_avg_delay = proc_event.sum_delay/proc_event.count;

			err = bpf_map_lookup_elem(sys_fd, &key, &sys_event);
			if (err < 0) {
				fprintf(stderr, "failed to lookup infos: %d\n", err);
				return -1;
			}
			sys_avg_delay = sys_event.sum_delay/sys_event.sum_count;

			printf("%02d:%02d:%02d  %-6d  %-6d  %-4d  | %-15lf %-15lf | %-15lf %-15lf | %-15lf %-15lf |\n",
					hour,min,sec,env.tgid,proc_event.pid,proc_event.prio,proc_avg_delay/1000000.0,sys_avg_delay/1000000.0,
					proc_event.max_delay/1000000.0,sys_event.max_delay/1000000.0,proc_event.min_delay/1000000.0,sys_event.min_delay/1000000.0);
			
			l_key = n_key;
		}
	}

	env.output_schedule = false;

	return 0;
}

static int print_syscall(void *ctx, void *data,unsigned long data_sz)
{
	const struct syscall_seq *e = data;
	u64 avg_delay;
	int tmp;
	time_t now = time(NULL);
	struct tm *localTime = localtime(&now);
    int hour = localTime->tm_hour;
    int min = localTime->tm_min;
    int sec = localTime->tm_sec;

	if(prev_image != SYSCALL_IMAGE){
        printf("SYSCALL -------------------------------------------------------------------------------------------------\n");
        printf("%-8s  %-6s  %-14s  %-14s  %-14s  %-13s  %-13s  %-8s\n",
				"TIME","PID","1st/num","2nd/num","3nd/num","AVG_DELAY(ns)","MAX_DELAY(ns)","SYSCALLS");

		prev_image = SYSCALL_IMAGE;
    }

	for(int i=0; i<e->count; i++){
		syscalls[e->record_syscall[i]] ++;

		if(e->record_syscall[i]==env.first_syscall || e->record_syscall[i]==env.second_syscall || e->record_syscall[i]==env.third_syscall){
			// 将前三名进行冒泡排序
			if(syscalls[env.third_syscall] > syscalls[env.second_syscall]){
				tmp = env.second_syscall;
				env.second_syscall = env.third_syscall;
				env.third_syscall = tmp;
			}
			if(syscalls[env.second_syscall] > syscalls[env.first_syscall]){
				tmp = env.first_syscall;
				env.first_syscall = env.second_syscall;
				env.second_syscall = tmp;
			}
			if(syscalls[env.third_syscall] > syscalls[env.second_syscall]){
				tmp = env.second_syscall;
				env.second_syscall = env.third_syscall;
				env.third_syscall = tmp;
			}
		}else if(syscalls[e->record_syscall[i]] > syscalls[env.third_syscall]){
			if(syscalls[e->record_syscall[i]] > syscalls[env.second_syscall]){
				if(syscalls[e->record_syscall[i]] > syscalls[env.first_syscall]){
					env.third_syscall = env.second_syscall;
					env.second_syscall = env.first_syscall;
					env.first_syscall = e->record_syscall[i];
					continue;
				}
				env.third_syscall = env.second_syscall;
				env.second_syscall = e->record_syscall[i];
				continue;
			}
			env.third_syscall = e->record_syscall[i];
		}
	}

	env.sum_delay += e->sum_delay;
	if(e->max_delay > env.max_delay)
		env.max_delay = e->max_delay;
	env.sum_count += e->count;
	avg_delay = env.sum_delay/env.sum_count;

	printf("%02d:%02d:%02d  %-6d  %-3d/%-10d  %-3d/%-10d  %-3d/%-10d  %-13lld  %-13lld  ",hour,min,sec,e->pid,
			env.first_syscall,syscalls[env.first_syscall],env.second_syscall,syscalls[env.second_syscall],
			env.third_syscall,syscalls[env.third_syscall],avg_delay,env.max_delay);
	
	for(int i=0; i<e->count; i++){
		if(i == e->count-1)	printf("%d\n",e->record_syscall[i]);
		else	printf("%d,",e->record_syscall[i]);
	}

	return 0;
}

static int print_lock(void *ctx, void *data,unsigned long data_sz)
{
	const struct lock_event *e = data;
	
	if(prev_image != LOCK_IMAGE){
        printf("USERLOCK ------------------------------------------------------------------------------------------------\n");
        printf("%-14s  %-6s  %-15s  %s\n","TIME","PID","LockAddr","LockStatus");

		prev_image = LOCK_IMAGE;
    }

	printf("%-14lld  %-6d  %-15lld  ",e->time,e->pid,e->lock_ptr);
	if(e->lock_status==2 || e->lock_status==5 || e->lock_status==8){
		printf("%s-%d\n",lock_status[e->lock_status],e->ret);
	}else{
		printf("%s\n",lock_status[e->lock_status]);
	}

	return 0;
}

static void inline quoted_symbol(char c) {
	switch(c) {
		case '"':
			putchar('\\');
			putchar('"');
			break;
		case '\t':
			putchar('\\');
			putchar('t');
			break;
		case '\n':
			putchar('\\');
			putchar('n');
			break;
		default:
			putchar(c);
			break;
	}
}

static void print_info1(const struct keytime_event *e)
{
	int i, args_counter = 0;

	if (env.quote)
		putchar('"');

	for (i = 0; i < e->info_size && args_counter < e->info_count; i++) {
		char c = e->char_info[i];

		if (env.quote) {
			if (c == '\0') {
				args_counter++;
				putchar('"');
				putchar(' ');
				if (args_counter < e->info_count) {
					putchar('"');
				}
			} else {
				quoted_symbol(c);
			}
		} else {
			if (c == '\0') {
				args_counter++;
				putchar(' ');
			} else {
				putchar(c);
			}
		}
	}
	if (e->info_count == env.max_args + 1) {
		fputs(" ...", stdout);
	}
}

static void print_info2(const struct keytime_event *e)
{
	int i=0;
	for(int tmp=e->info_count; tmp>0 ; tmp--){
		if(env.quote){
			printf("\"%llu\" ",e->info[i++]);
		}else{
			printf("%llu ",e->info[i++]);
		}
	}
}

static int print_keytime(void *ctx, void *data,unsigned long data_sz)
{
	const struct keytime_event *e = data;
	time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    int hour = localTime->tm_hour;
    int min = localTime->tm_min;
    int sec = localTime->tm_sec;
	
	if(prev_image != KEYTIME_IMAGE){
        printf("KEYTIME -------------------------------------------------------------------------------------------------\n");
        printf("%-8s  %-6s  %-15s  %s\n","TIME","PID","EVENT","ARGS/RET/OTHERS");

		prev_image = KEYTIME_IMAGE;
    }

	printf("%02d:%02d:%02d  %-6d  %-15s  ",hour,min,sec,e->pid,keytime_type[e->type]);
	if(e->type==4 || e->type==5 || e->type==6 || e->type==7 || e->type==8 || e->type==9){
		printf("child_pid:");
	}
	if(e->enable_char_info){
		print_info1(e);
	}else{
		print_info2(e);
	}

	putchar('\n');

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int lock_attach(struct lock_image_bpf *skel)
{
	int err;
	
	ATTACH_UPROBE_CHECKED(skel,pthread_mutex_lock,pthread_mutex_lock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_mutex_lock,pthread_mutex_lock_exit);
	ATTACH_UPROBE_CHECKED(skel,__pthread_mutex_trylock,__pthread_mutex_trylock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_mutex_trylock,__pthread_mutex_trylock_exit);
	ATTACH_UPROBE_CHECKED(skel,pthread_mutex_unlock,pthread_mutex_unlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_mutex_unlock,pthread_mutex_unlock_exit);
	
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_rdlock,__pthread_rwlock_rdlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_rdlock,__pthread_rwlock_rdlock_exit);
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_tryrdlock,__pthread_rwlock_tryrdlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_tryrdlock,__pthread_rwlock_tryrdlock_exit);
	
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_wrlock,__pthread_rwlock_wrlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_wrlock,__pthread_rwlock_wrlock_exit);
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_trywrlock,__pthread_rwlock_trywrlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_trywrlock,__pthread_rwlock_trywrlock_exit);
	
	ATTACH_UPROBE_CHECKED(skel,__pthread_rwlock_unlock,__pthread_rwlock_unlock_enter);
	ATTACH_URETPROBE_CHECKED(skel,__pthread_rwlock_unlock,__pthread_rwlock_unlock_exit);
	
	err = lock_image_bpf__attach(skel);
	CHECK_ERR(err, "Failed to attach BPF lock skeleton");
	
	return 0;
}

static int keytime_attach(struct keytime_image_bpf *skel)
{
	int err;

	ATTACH_URETPROBE_CHECKED(skel,fork,fork_exit);
	ATTACH_URETPROBE_CHECKED(skel,vfork,vfork_exit);
	ATTACH_UPROBE_CHECKED(skel,pthread_create,pthread_create_enter);
	ATTACH_URETPROBE_CHECKED(skel,pthread_create,pthread_create_exit);

	err = keytime_image_bpf__attach(skel);
	CHECK_ERR(err, "Failed to attach BPF keytime skeleton");

	return 0;
}

void *enable_function(void *arg) {
    env.create_thread = true;
    sleep(1);
    if(env.enable_resource)	env.output_resourse = true;
	if(env.enable_schedule)	env.output_schedule = true;
    env.create_thread = false;
    env.exit_thread = true;

    return NULL;
}

static void sig_handler(int signo)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	//struct resource_image_bpf *resource_skel = NULL;
	struct syscall_image_bpf *syscall_skel = NULL;
	struct ring_buffer *syscall_rb = NULL;
	struct lock_image_bpf *lock_skel = NULL;
	struct ring_buffer *lock_rb = NULL;
	struct keytime_image_bpf *keytime_skel = NULL;
	struct ring_buffer *keytime_rb = NULL;
	struct schedule_image_bpf *schedule_skel = NULL;
	pthread_t thread_enable;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	
	env.ignore_tgid = getpid();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	signal(SIGALRM,sig_handler);

	if(env.enable_resource){
#if 0
		resource_skel = resource_image_bpf__open();
		if(!resource_skel) {
			fprintf(stderr, "Failed to open BPF resource skeleton\n");
			return 1;
		}

		resource_skel->rodata->target_pid = env.pid;
		resource_skel->rodata->target_cpu_id = env.cpu_id;
		if(!env.enable_myproc)	resource_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = resource_image_bpf__load(resource_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF resource skeleton\n");
			goto cleanup;
		}

		err = resource_image_bpf__attach(resource_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF resource skeleton\n");
			goto cleanup;
		}
#endif
	}

	if(env.enable_syscall){
		syscall_skel = syscall_image_bpf__open();
		if(!syscall_skel) {
			fprintf(stderr, "Failed to open BPF syscall skeleton\n");
			return 1;
		}

		syscall_skel->rodata->target_pid = env.pid;
		syscall_skel->rodata->syscalls = env.syscalls;
		if(!env.enable_myproc)	syscall_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = syscall_image_bpf__load(syscall_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF syscall skeleton\n");
			goto cleanup;
		}

		err = syscall_image_bpf__attach(syscall_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF syscall skeleton\n");
			goto cleanup;
		}

		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		syscall_rb = ring_buffer__new(bpf_map__fd(syscall_skel->maps.syscall_rb), print_syscall, NULL, NULL);
		if (!syscall_rb) {
			err = -1;
			fprintf(stderr, "Failed to create syscall ring buffer\n");
			goto cleanup;
		}
	}

	if(env.enable_lock){
		lock_skel = lock_image_bpf__open();
		if (!lock_skel) {
			fprintf(stderr, "Failed to open BPF lock skeleton\n");
			return 1;
		}

		if(!env.enable_myproc)	lock_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = lock_image_bpf__load(lock_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF lock skeleton\n");
			goto cleanup;
		}
		
		/* 附加跟踪点处理程序 */
		err = lock_attach(lock_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF lock skeleton\n");
			goto cleanup;
		}
		
		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		lock_rb = ring_buffer__new(bpf_map__fd(lock_skel->maps.lock_rb), print_lock, NULL, NULL);
		if (!lock_rb) {
			err = -1;
			fprintf(stderr, "Failed to create lock ring buffer\n");
			goto cleanup;
		}
	}

	if(env.enable_keytime){
		keytime_skel = keytime_image_bpf__open();
		if (!keytime_skel) {
			fprintf(stderr, "Failed to open BPF keytime skeleton\n");
			return 1;
		}

		keytime_skel->rodata->target_pid = env.pid;
		if(!env.enable_myproc)	keytime_skel->rodata->ignore_tgid = env.ignore_tgid;

		err = keytime_image_bpf__load(keytime_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF keytime skeleton\n");
			goto cleanup;
		}
		
		/* 附加跟踪点处理程序 */
		err = keytime_attach(keytime_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF keytime skeleton\n");
			goto cleanup;
		}
		
		/* 设置环形缓冲区轮询 */
		//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		keytime_rb = ring_buffer__new(bpf_map__fd(keytime_skel->maps.keytime_rb), print_keytime, NULL, NULL);
		if (!keytime_rb) {
			err = -1;
			fprintf(stderr, "Failed to create keytime ring buffer\n");
			goto cleanup;
		}
	}

	if(env.enable_schedule){
		schedule_skel = schedule_image_bpf__open();
		if(!schedule_skel) {
			fprintf(stderr, "Failed to open BPF schedule skeleton\n");
			return 1;
		}

		schedule_skel->rodata->target_pid = env.pid;
		schedule_skel->rodata->target_tgid = env.tgid;
		schedule_skel->rodata->target_cpu_id = env.cpu_id;

		err = schedule_image_bpf__load(schedule_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF schedule skeleton\n");
			goto cleanup;
		}

		err = schedule_image_bpf__attach(schedule_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF schedule skeleton\n");
			goto cleanup;
		}
	}

	/* 处理事件 */
	while (!exiting) {
		if(env.enable_resource || env.enable_schedule){
			// 等待新线程结束，回收资源
			if(env.exit_thread){
				env.exit_thread = false;
				if (pthread_join(thread_enable, NULL) != 0) {
					perror("pthread_join");
					exit(EXIT_FAILURE);
				}
			}

			// 创建新线程，设置 output
			if(!env.create_thread){
				if (pthread_create(&thread_enable, NULL, enable_function, NULL) != 0) {
					perror("pthread_create");
					exit(EXIT_FAILURE);
				}
			}
		}

		if(env.enable_resource && env.output_resourse){
			//err = print_resource(resource_skel->maps.total);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				break;
			}
		}

		if(env.enable_syscall){
			err = ring_buffer__poll(syscall_rb, 0);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling syscall ring buffer: %d\n", err);
				break;
			}
		}

		if(env.enable_lock){
			err = ring_buffer__poll(lock_rb, 0);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling lock ring buffer: %d\n", err);
				break;
			}
		}

		if(env.enable_keytime){
			err = ring_buffer__poll(keytime_rb, 0);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling keytime ring buffer: %d\n", err);
				break;
			}
		}

		if(env.enable_schedule && env.output_schedule){
			err = print_schedule(schedule_skel->maps.proc_schedule,schedule_skel->maps.target_schedule,
								 schedule_skel->maps.tg_schedule,schedule_skel->maps.sys_schedule);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				break;
			}
		}
	}

/* 卸载BPF程序 */
cleanup:
	//resource_image_bpf__destroy(resource_skel);
	ring_buffer__free(syscall_rb);
	syscall_image_bpf__destroy(syscall_skel);
	ring_buffer__free(lock_rb);
	lock_image_bpf__destroy(lock_skel);
	ring_buffer__free(keytime_rb);
	keytime_image_bpf__destroy(keytime_skel);
	schedule_image_bpf__destroy(schedule_skel);

	return err < 0 ? -err : 0;
}