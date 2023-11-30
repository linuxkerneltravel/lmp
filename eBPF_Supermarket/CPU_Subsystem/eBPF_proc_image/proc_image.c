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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "include/proc_image.h"
#include "proc_image.skel.h"

#include <sys/utsname.h>

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

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile bool exiting = false;
static const char object[] = "/usr/lib/x86_64-linux-gnu/libc.so.6";
static struct env {
	int pid;
	int time;
	int cpu_id;
    bool enable_cputime;
    bool enable_execve;
    bool enable_exit;
    bool quote;
    int max_args;
    bool enable_u_mutex;
	bool enable_k_mutex;
	bool enable_u_rwlock_rd;
	bool enable_u_rwlock_wr;
    bool enable_fork;
	bool enable_vfork;
	bool enable_newthread;
} env = {
    .pid = 0,
	.time = 0,
	.cpu_id = 0,
    .enable_cputime = false,
    .enable_execve = false,
	.enable_exit = false,
	.quote = false,
	.max_args = DEFAULT_MAXARGS,
    .enable_u_mutex = false,
	.enable_k_mutex = false,
	.enable_u_rwlock_rd = false,
	.enable_u_rwlock_wr = false,
    .enable_fork = false,
	.enable_vfork = false,
	.enable_newthread = false,
};

const char argp_program_doc[] ="Trace process to get process image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{ "cpuid", 'C', "CPUID", 0, "Set For Tracing  per-CPU Process(other processes don't need to set this parameter)" },
    { "cputime", 'c', NULL, 0, "Process on_off_CPU time information" },
    { "execve", 'e', NULL, 0, "Trace execve syscall of the process" },
	{ "exit", 'E', NULL, 0, "Trace exit syscall of the process" },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments" },
    { "keytime", 'K',NULL, 0, "Trace process key time" },
	{ "user-mutex", 'm', NULL, 0, "process user mutex image" },
	{ "kernel-mutex", 'M', NULL, 0, "process kernel mutex image" },
	{ "user-rwlock-rd", 'r', NULL, 0, "process user rwlock image in read mode" },
	{ "user-rwlock-wr", 'w', NULL, 0, "process user rwlock image in write mode" },
    { "lock", 'L', NULL, 0, "Trace process lock information" },
    { "fork", 'f', NULL, 0, "the child process image of fork" },
	{ "vfork", 'F', NULL, 0, "the child process image of vfork" },
	{ "newthread", 'T', NULL, 0, "the new thread image" },
    { "child", 'S',NULL, 0, "Trace process child information" },
	{ "all", 'A',NULL, 0, "Enable all functions for process image" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
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
		case 't':
				env.time = strtol(arg, NULL, 10);
				if(env.time) alarm(env.time);
				break;
		case 'C':
				cpu_id = strtol(arg, NULL, 10);
				if(cpu_id < 0){
					warn("Invalid CPUID: %s\n", arg);
					argp_usage(state);
				}
				env.cpu_id = cpu_id;
				break;
        case 'c':
                env.enable_cputime = true;
                break;
 		case 'e':
				env.enable_execve = true;
				break;
		case 'E':
				env.enable_exit = true;
				break;
		case 'q':
				env.quote = true;
				break;
        case 'K':
                env.enable_execve = true;
				env.enable_exit = true;
                break;
        case 'm':
				env.enable_u_mutex = true;
				break;
		case 'M':
				env.enable_k_mutex = true;
				break;
		case 'r':
				env.enable_u_rwlock_rd = true;
				break;
		case 'w':
				env.enable_u_rwlock_wr = true;
				break;
        case 'L':
                env.enable_u_mutex = true;
				env.enable_k_mutex = true;
				env.enable_u_rwlock_rd = true;
				env.enable_u_rwlock_wr = true;
				break;
        case 'f':
				env.enable_fork = true;
				break;
		case 'F':
				env.enable_vfork = true;
				break;
		case 'T':
				env.enable_newthread = true;
				break;
        case 'S':
                env.enable_fork = true;
				env.enable_vfork = true;
				env.enable_newthread = true;
                break;
		case 'A':
				env.enable_cputime = true;
				env.enable_execve = true;
				env.enable_exit = true;
				env.enable_u_mutex = true;
				env.enable_k_mutex = true;
				env.enable_u_rwlock_rd = true;
				env.enable_u_rwlock_wr = true;
				env.enable_fork = true;
				env.enable_vfork = true;
				env.enable_newthread = true;
				env.quote = true;
				break;
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
		default:
				return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

static void sig_handler(int signo)
{
	exiting = 1;
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

static void print_args1(const struct event *e, bool quote)
{
	int i, args_counter = 0;

	if (env.quote)
		putchar('"');

	for (i = 0; i < e->args_size && args_counter < e->args_count; i++) {
		char c = e->args[i];

		if (env.quote) {
			if (c == '\0') {
				args_counter++;
				putchar('"');
				putchar(' ');
				if (args_counter < e->args_count) {
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
	if (e->args_count == env.max_args + 1) {
		fputs(" ...", stdout);
	}
}

static void print_args2(const struct event *e)
{
	int i=0;
	for(int tmp=e->args_count; tmp>0 ; tmp--){
		if(env.quote){
			printf("\"%llu\" ",e->ctx_args[i++]);
		}else{
			printf("%llu ",e->ctx_args[i++]);
		}
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char *c;
	char *pad = "\\";
	char *miss = "miss";
	double time;

	switch (e->type) {
        case 1:
			c = "on_cpu";
            break;
		case 2:
			c = "off_cpu";
			break;
		case 3:
			c = "exec_enter";
			break;
		case 4:
			c = "exec_exit";
			break;
		case 5:
			c = "exit_enter";
			break;
		case 6:
			c = "umutex_req";
			break;
		case 7:
			c = "umutex_lock";
			break;
		case 8:
			c = "umutex_unlock";
			break;
		case 9:
			c = "kmutex_req";
			break;
		case 10:
			c = "kmutex_lock";
			break;
		case 11:
			c = "kmutex_unlock";
			break;
		case 12:
			c = "rdlock_req";
			break;
		case 13:
			c = "rdlock_lock";
			break;
		case 14:
			c = "rdlock_unlock";
			break;
		case 15:
			c = "wrlock_req";
			break;
		case 16:
			c = "wrlock_lock";
			break;
		case 17:
			c = "wrlock_unlock";
			break;
		case 18:
			c = "fork_begin";
			break;
		case 19:
			c = "fork_end";
			break;
		case 20:
			c = "vfork_begin";
			break;
		case 21:
			c = "vfork_end";
			break;
		case 22:
			c = "pthread_begin";
			break;
		case 23:
			c = "pthread_end";
			break;
        default:
            c = "?";
    }

	if(e->start!=0 && e->exit!=0){
		time = (e->exit - e->start)*1.0/1000.0;
		printf("%-15llu %-15s %-16s %-6d %-6d %-3d %-15.3lf ", e->exit, c, e->comm, e->pid, e->ppid, e->cpu_id, time);
	}else if(e->start==0 && e->exit!=0){
		printf("%-15llu %-15s %-16s %-6d %-6d %-3d %-15s ", e->exit, c, e->comm, e->pid, e->ppid, e->cpu_id, miss);
	}else{
		printf("%-15llu %-15s %-16s %-6d %-6d %-3d %-15s ", e->start, c, e->comm, e->pid, e->ppid, e->cpu_id, pad);
	}

	if(e->type==1 || e->type==2 || (e->type>=18 && e->type<=23)){
		printf("\\   \\");
	}

	if(e->type==3 || e->type==4 || e->type==5){
		if(e->start!=0 && e->exit!=0){
			printf("%-3d ",e->retval);
			if(e->enable_char_args){
				print_args1(e, env.quote);
			}else{
				print_args2(e);
			}
		}else if(e->start==0 && e->exit!=0){
			printf("%-3d %s", e->retval,pad);
		}else{
			printf("%-3s ",pad);
			if(e->enable_char_args){
				print_args1(e, env.quote);
			}else{
				print_args2(e);
			}
		}
	}

	if(e->type==6 || e->type==9 || e->type==12 || e->type==15){
		printf("\\   ");
		print_args2(e);
	}

	if(e->type==7 || e->type==8 || e->type==10 || e->type==11 ||
	   e->type==13 || e->type==14 || e->type==16 || e->type==17){
		printf("%-3d ",e->retval);
		print_args2(e);
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

static int attach(struct proc_image_bpf *skel)
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

	ATTACH_URETPROBE_CHECKED(skel,fork,fork_exit);
	ATTACH_URETPROBE_CHECKED(skel,vfork,vfork_exit);
	
	err = proc_image_bpf__attach(skel);
	CHECK_ERR(err, "Failed to attach BPF skeleton");
	
	return 0;
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct proc_image_bpf *skel;
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

	/* 打开BPF应用程序 */
	skel = proc_image_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_pid = env.pid;
	skel->rodata->target_cpu_id = env.cpu_id;
	skel->rodata->enable_cputime = env.enable_cputime;
	skel->rodata->enable_execve = env.enable_execve;
	skel->rodata->enable_exit = env.enable_exit;
	skel->rodata->enable_u_mutex = env.enable_u_mutex;
	skel->rodata->enable_k_mutex = env.enable_k_mutex;
	skel->rodata->enable_u_rwlock_rd = env.enable_u_rwlock_rd;
	skel->rodata->enable_u_rwlock_wr = env.enable_u_rwlock_wr;
	skel->rodata->enable_fork = env.enable_fork;
	skel->rodata->enable_vfork = env.enable_vfork;
	skel->rodata->enable_newthread = env.enable_newthread;

	/* 加载并验证BPF程序 */
	err = proc_image_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* 附加跟踪点处理程序 */
	err = attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("%-15s %-15s %-16s %-6s %-6s %-3s %-15s %3s %s\n", "TIME", "TYPE", "COMM", "PID", "PPID", "CPU", "time(us)", "RET", "ARGS");

	struct utsname uname_data;

    if (uname(&uname_data) == -1) {
        perror("uname");
        return 1;
    }

    printf("Kernel Version: %s\n", uname_data.release);

	/* 设置事件回调 */
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* 如果退出，将err重置为返回0 */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	proc_image_bpf__destroy(skel);

	return err != 0;
}
