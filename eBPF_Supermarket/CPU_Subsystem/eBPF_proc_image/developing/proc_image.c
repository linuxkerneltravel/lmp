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
#include "syscall_image.skel.h"

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
	bool enable_syscall;
} env = {
    .pid = -1,
    .cpu_id = -1,
    .time = 0,
	.enable_output = false,
	.create_thread = false,
	.exit_thread = false,
    .enable_resource = false,
	.first_rsc = true,
	.enable_syscall = false,
};

/*
// 定义定时器结构体和定时器ID
static struct sigevent sev;
static struct itimerspec its;
static timer_t timerid;
*/

static struct timespec prevtime;
static struct timespec currentime;

const char argp_program_doc[] ="Trace process to get process image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
    { "cpuid", 'c', "CPUID", 0, "Set For Tracing  per-CPU Process(other processes don't need to set this parameter)" },
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
    { "resource", 'r', NULL, 0, "Collects resource usage information about processes" },
	{ "syscall", 's', NULL, 0, "Collects syscall sequence information about processes" },
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
        case 'r':
                env.enable_resource = true;
                break;
		case 's':
                env.enable_syscall = true;
                break;
        default:
				return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

/*
// 定时器处理函数
void timer_handler(int signo) {
	env.enable_output = true;
}
*/

static void sig_handler(int signo)
{
	exiting = 1;
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
			printf("%-8s  %-6s  %-6s  %-6s  %-6s  %-12s  %-12s\n","TIME","PID","CPU-ID","CPU(%)","MEM(%)","read(kb/s)","write(kb/s)");
			prev_image = RESOURCE_IMAGE;
		}

		err = bpf_map_lookup_elem(fd, &next_key, &event);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}
		
		clock_gettime(CLOCK_REALTIME, &currentime);
		interval = currentime.tv_nsec-prevtime.tv_nsec+(currentime.tv_sec-prevtime.tv_sec)*1000000000;

		pcpu = (100.0*event.time)/interval;
		pmem = (100.0*event.memused)/memtotal;
		read_rate = (1.0*event.readchar)/1024/((1.0*event.time)/1000000000);            // kb/s
		write_rate = (1.0*event.writechar)/1024/((1.0*event.time)/1000000000);          // kb/s
		
		if(pcpu<=100 && pmem<=100){
			printf("%02d:%02d:%02d  %-6d  %-6d  %-6.3f  %-6.3f  %-12.2lf  %-12.2lf\n",
					hour,min,sec,event.pid,event.cpu_id,pcpu,pmem,read_rate,write_rate);
		}
		
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
/*
	// 重新启动定时器
    timer_settime(timerid, 0, &its, NULL);
*/

	return 0;
}

static void print_syscall(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct syscall_seq *e = data;
	int count = e->count;

	if(count == 0)	return;

	if(prev_image != SYSCALL_IMAGE){
        printf("SYSCALL------------------------------------------------------------\n");
        printf("%-29s  %-6s  %-8s\n","TIME(oncpu-offcpu)","PID","syscalls");

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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 新线程的执行函数
void *thread_function(void *arg) {
    env.create_thread = 1;
    sleep(1);
    env.enable_output = true;
    env.create_thread = 0;
    env.exit_thread = 1;

    return NULL;
}

int main(int argc, char **argv)
{
	struct resource_image_bpf *resource_skel;
	struct syscall_image_bpf *syscall_skel;
	struct perf_buffer *syscall_pb = NULL;
	pthread_t thread_id;
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

	/* 更干净地处理Ctrl-C
	   SIGINT：由Interrupt Key产生，通常是CTRL+C或者DELETE。发送给所有ForeGround Group的进程
	   SIGTERM：请求中止进程，kill命令发送
	*/
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGALRM,sig_handler);

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

/*
		// 设置定时器处理函数
		sev.sigev_notify = SIGEV_SIGNAL;
		sev.sigev_signo = SIGALRM;
		sev.sigev_value.sival_ptr = &timerid;
		// 注册SIGALRM信号的处理函数为timer_handler
		signal(SIGALRM, timer_handler);

		// 创建定时器
		timer_create(CLOCK_REALTIME, &sev, &timerid);

		// 设置初次定时器到期时间为1秒
		its.it_value.tv_sec = 1;
		its.it_value.tv_nsec = 0;

		// 启动定时器
		timer_settime(timerid, 0, &its, NULL);
*/
	}

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

	/* 处理事件 */
	while (!exiting) {
		// 等待新线程结束，回收资源
        if(env.exit_thread){
            env.exit_thread = 0;
            if (pthread_join(thread_id, NULL) != 0) {
                perror("pthread_join");
                exit(EXIT_FAILURE);
            }
        }

		// 创建新线程，设置 env.enable_output
        if(!env.create_thread){
            if (pthread_create(&thread_id, NULL, thread_function, NULL) != 0) {
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

		if(env.enable_syscall){
			err = perf_buffer__poll(syscall_pb, 0);
			if (err < 0 && err != -EINTR) {
				fprintf(stderr, "error polling syscall perf buffer: %s\n", strerror(-err));
				goto cleanup;
			}
			err = 0;
		}
	}

/* 卸载BPF程序 */
cleanup:
	resource_image_bpf__destroy(resource_skel);
	perf_buffer__free(syscall_pb);
	syscall_image_bpf__destroy(syscall_skel);
	
	return err < 0 ? -err : 0;
}