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
#include "proc_image.h"
#include "resource_image.skel.h"
/*
#include "syscall_image.skel.h"
*/
#include "lock_image.skel.h"

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
    do                                                           \
    {                                                            \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,                \
                    .retprobe = is_retprobe,                     \
                    .func_name = #sym_name);                     \
        skel->links.prog_name = bpf_program__attach_uprobe_opts( \
            skel->progs.prog_name,                               \
            env.pid,                                                 \
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

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

#define CHECK_ERR(cond, info)                               \
    if (cond)                                               \
    {                                                       \
        fprintf(stderr, "[%s]" info "\n", strerror(errno));                                   \
        return -1;                                          \
    }

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100

#define RESOURCE_IMAGE 1
#define SYSCALL_IMAGE 2
#define LOCK_IMAGE 3

static int prev_image = 0;
static volatile bool exiting = false;
static const char object[] = "/usr/lib/x86_64-linux-gnu/libc.so.6";
static struct env {
    int pid;
    int cpu_id;
    int time;
	bool enable_output;
	bool create_thread;
	bool exit_thread;
    bool enable_resource;
	bool first_rsc;
//	bool enable_syscall;
	bool enable_lock;
} env = {
    .pid = -1,
    .cpu_id = -1,
    .time = 0,
	.enable_output = false,
	.create_thread = false,
	.exit_thread = false,
    .enable_resource = false,
	.first_rsc = true,
//	.enable_syscall = false,
	.enable_lock = false,
};

static struct timespec prevtime;
static struct timespec currentime;

char *lock_status[] = {"", "mutex_req", "mutex_lock", "mutex_unlock",
						   "rdlock_req", "rdlock_lock", "rdlock_unlock",
						   "wrlock_req", "wrlock_lock", "wrlock_unlock"};

const char argp_program_doc[] ="Trace process to get process image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
    { "cpuid", 'c', "CPUID", 0, "Set For Tracing  per-CPU Process(other processes don't need to set this parameter)" },
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{ "all", 'a', NULL, 0, "Start all functions" },
    { "resource", 'r', NULL, 0, "Collects resource usage information about processes" },
	{ "syscall", 's', NULL, 0, "Collects syscall sequence information about processes" },
	{ "lock", 'l', NULL, 0, "Collects lock information about processes" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;
	long cpu_id;
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
		case 'a':
				env.enable_resource = true;
//				env.enable_syscall = true;
				env.enable_lock = true;
				break;
        case 'r':
                env.enable_resource = true;
                break;
/*		case 's':
                env.enable_syscall = true;
                break;*/
		case 'l':
                env.enable_lock = true;
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
			printf("RESOURCE------------------------------------------------------------\n");
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
	env.enable_output = false;

	return 0;
}

/*
static void print_syscall(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct syscall_seq *e = data;
	int count = e->count;

	if(count == 0)	return;

	if(prev_image != SYSCALL_IMAGE){
        printf("SYSCALL------------------------------------------------------------\n");
        printf("%-29s  %-6s  %-8s\n","TIME(oncpu-offcpu)","PID","SYSCALLS");

		prev_image = SYSCALL_IMAGE;
    }

	printf("%-14lld-%14lld  %-6d  ",e->oncpu_time,e->offcpu_time,e->pid);
	for(int i=0; i<count; i++){
		if(i == count-1)	printf("%ld",e->record_syscall[i]);
		else	printf("%ld,",e->record_syscall[i]);
	}

	putchar('\n');
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}
*/

static int print_lock(void *ctx, void *data,unsigned long data_sz)
{
	const struct lock_event *e = data;
	
	if(prev_image != LOCK_IMAGE){
        printf("USERLOCK------------------------------------------------------------\n");
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int attach(struct lock_image_bpf *skel)
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

// 新线程的执行函数
void *enable_function(void *arg) {
    env.create_thread = true;
    sleep(1);
    env.enable_output = true;
    env.create_thread = false;
    env.exit_thread = true;

    return NULL;
}

void *signal_function(void *arg) {
	/* 更干净地处理Ctrl-C
	   SIGINT：由Interrupt Key产生，通常是CTRL+C或者DELETE。发送给所有ForeGround Group的进程
	   SIGTERM：请求中止进程，kill命令发送
	*/
	int sig;
	sigset_t set;
	
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGALRM);
	// 等待多个信号中的一个到来
	sigwait(&set, &sig);

	exiting = true;

	return NULL;
}

int main(int argc, char **argv)
{
	struct resource_image_bpf *resource_skel;
/*
	struct syscall_image_bpf *syscall_skel;
	struct perf_buffer *syscall_pb = NULL;
*/
	struct ring_buffer *lock_rb = NULL;
	struct lock_image_bpf *lock_skel;
	pthread_t thread_enable;
	pthread_t thread_signal;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	// 使用线程接受信号，设置 exiting 变量
	// 避免主进程过度频繁打印无法接受信号
	if (pthread_create(&thread_signal, NULL, signal_function, NULL) != 0) {
		perror("pthread_create");
		exit(EXIT_FAILURE);
	}

	if(env.enable_resource){
		resource_skel = resource_image_bpf__open();
		if(!resource_skel) {
			fprintf(stderr, "Failed to open BPF resource skeleton\n");
			return 1;
		}

		resource_skel->rodata->target_pid = env.pid;
		resource_skel->rodata->target_cpu_id = env.cpu_id;

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

	}

/*
	if(env.enable_syscall){
		syscall_skel = syscall_image_bpf__open();
		if(!syscall_skel) {
			fprintf(stderr, "Failed to open BPF syscall skeleton\n");
			return 1;
		}

		syscall_skel->rodata->target_pid = env.pid;

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

		syscall_pb = perf_buffer__new(bpf_map__fd(syscall_skel->maps.syscalls), PERF_BUFFER_PAGES,
			      print_syscall, handle_lost_events, NULL, NULL);
		if (!syscall_pb) {
			err = -errno;
			fprintf(stderr, "failed to open syscall perf buffer: %d\n", err);
			goto cleanup;
		}
	}
*/

	if(env.enable_lock){
		lock_skel = lock_image_bpf__open();
		if (!lock_skel) {
			fprintf(stderr, "Failed to open BPF lock skeleton\n");
			return 1;
		}

		err = lock_image_bpf__load(lock_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF lock skeleton\n");
			goto cleanup;
		}
		
		/* 附加跟踪点处理程序 */
		err = attach(lock_skel);
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

	/* 处理事件 */
	while (!exiting) {
		// 等待新线程结束，回收资源
        if(env.exit_thread){
            env.exit_thread = false;
            if (pthread_join(thread_enable, NULL) != 0) {
                perror("pthread_join");
                exit(EXIT_FAILURE);
            }
        }

		// 创建新线程，设置 env.enable_output
        if(!env.create_thread){
            if (pthread_create(&thread_enable, NULL, enable_function, NULL) != 0) {
                perror("pthread_create");
                exit(EXIT_FAILURE);
            }
        }

		if(env.enable_resource && env.enable_output){
			err = print_resource(resource_skel->maps.total);
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				break;
			}
		}

/*
		if(env.enable_syscall){
			err = perf_buffer__poll(syscall_pb, 0);
			if (err < 0 && err != -EINTR) {
				fprintf(stderr, "error polling syscall perf buffer: %s\n", strerror(-err));
				goto cleanup;
			}
			err = 0;
		}
*/
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
	}

/* 卸载BPF程序 */
cleanup:
	resource_image_bpf__destroy(resource_skel);
/*
	perf_buffer__free(syscall_pb);
	syscall_image_bpf__destroy(syscall_skel);
*/
	ring_buffer__free(lock_rb);
	lock_image_bpf__destroy(lock_skel);

	return err < 0 ? -err : 0;
}