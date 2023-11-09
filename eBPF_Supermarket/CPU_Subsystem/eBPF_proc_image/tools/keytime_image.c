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
// user-mode code for the process key time image

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
#include "keytime_image.h"
#include "keytime_image.skel.h"

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100
#define MAX_ARGS_KEY 259
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static struct env {
	int pid;
	int time;
	bool enable_execve;
	bool enable_exit;
	bool quote;
	int max_args;
} env = {
	.pid = 0,
	.time = 0,
	.enable_execve = false,
	.enable_exit = false,
	.quote = false,
	.max_args = DEFAULT_MAXARGS,
};

const char argp_program_doc[] ="Trace process to get process key time image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{ "execve", 'e', NULL, 0, "Trace execve syscall of the process" },
	{ "exit", 'E', NULL, 0, "Trace exit syscall of the process" },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;
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
 		case 'e':
				env.enable_execve = true;
				break;
		case 'E':
				env.enable_exit = true;
				break;
		case 'q':
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

static void print_args(const struct event *e, bool quote)
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

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char *c;
	char *pad = "\\";
	char *miss = "miss";
	double time;

	switch (e->flag) {
        case 1:
			c = "execve_enter";
            break;
		case 2:
			c= "execve_exit";
			break;
		case 3:
			c= "exit";
			break;
        default:
            c = "?";
    }

	if(e->start!=0 && e->exit!=0){
		time = (e->exit - e->start)*1.0/1000.0;
		printf("%-15llu %-15s %-16s %-6d %-6d %-15.3lf %-3d ", e->exit, c, e->comm, e->pid, e->ppid, time, e->retval);
	}else if(e->start==0 && e->exit!=0){
		printf("%-15llu %-15s %-16s %-6d %-6d %-15s %-3d \\\n", e->exit, c, e->comm, e->pid, e->ppid, miss, e->retval);
		return;
	}else{
		printf("%-15llu %-15s %-16s %-6d %-6d %-15s %-3s ", e->start, c, e->comm, e->pid, e->ppid, pad, pad);
	}

	if(e->enable_char_args){
		print_args(e, env.quote);
	}else{
		int i=0;
		for(int tmp=e->args_count; tmp>0 ; tmp--){
			if(env.quote){
				printf("\"%ld\" ",e->ctx_args[i++]);
			}else{
				printf("%ld ",e->ctx_args[i++]);
			}
		}
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

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct keytime_image_bpf *skel;
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
	skel = keytime_image_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_pid = env.pid;
	skel->rodata->enable_execve = env.enable_execve;
	skel->rodata->enable_exit = env.enable_exit;

	/* 加载并验证BPF程序 */
	err = keytime_image_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* 附加跟踪点处理程序 */
	err = keytime_image_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("%-15s %-15s %-16s %-6s %-6s %-15s %3s %s\n", "TIME", "SYSCALL", "PCOMM", "PID", "PPID", "time(us)", "RET", "ARGS");

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
	keytime_image_bpf__destroy(skel);

	return err != 0;
}
