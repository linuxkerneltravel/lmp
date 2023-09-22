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
// user-mode code for the process life cycle image

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <argp.h>
#include <errno.h>
#include "lifecycle_image.skel.h"
#include "lifecycle_image.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile bool exiting = false;

static struct env {
	int pid;
	int time;
	int cpu_id;
	int stack_count;
	bool set_stack;
	bool enable_cs;
} env = {
	.pid = 0,
	.time = 0,
	.cpu_id = 0,
	.stack_count = 0,
	.set_stack = false,
	.enable_cs = false,
};

static struct ksyms *ksyms = NULL;

const char argp_program_doc[] ="Trace process to get process life cycle image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "cpuid", 'C', "CPUID", 0, "Set For Tracing Process 0(other processes don't need to set this parameter)" },
	{ "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{ "cs-reason", 'r', NULL, 0, "Process context switch reasons annotation" },
	{ "stack", 's', "STACK-COUNT", 0, "The number of kernel stacks printed when the process is under the CPU" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;
	long cpu_id;
	long stack;
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
		case 'C':
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
				env.enable_cs = true;
				break;
		case 's':
				stack = strtol(arg, NULL, 10);
				if (stack < 0) {
					warn("Invalid STACK-COUNT: %s\n", arg);
					// 调用argp_usage函数，用于打印用法信息并退出程序
					argp_usage(state);
				}
				env.stack_count = stack;
				env.set_stack = true;
				break;
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
		default:
				return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_stack(unsigned long long address)
{
	const struct ksym *ksym;

	ksym = ksyms__map_addr(ksyms, address);
	if (ksym)
		printf("0x%llx %s+0x%llx\n", address, ksym->name, address - ksym->addr);
	else
		printf("0x%llx [unknown]\n", address);
}

static int handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct cpu_event *e = data;
	double time;

	if(e->flag == 1){
		time = (e->offcpu_time - e->oncpu_time)*1.0/1000000000.0;
		printf("flag:%d  pid:%d  comm:%s  oncpu_id :%d  oncpu_time(ns) :%llu  offcpu_id:%d  offcpu_time(ns):%llu  time(s):%lf\n",
		e->flag,e->pid,e->comm,e->oncpu_id,e->oncpu_time,e->offcpu_id,e->offcpu_time,time);
	
		if(env.enable_cs){
			printf("pid:%d,comm:%s,prio:%d -> pid:%d,comm:%s,prio:%d\n", e->pid,e->comm,e->prio,e->n_pid,e->n_comm,e->n_prio);
			int count = e->kstack_sz / sizeof(long long unsigned int);
			if(!env.set_stack)	env.stack_count = count;
			if(e->kstack_sz>0 && env.stack_count!=0){
				int t_count = env.stack_count;
	
				if(env.stack_count > count)
				{
					t_count = count;
				}
				printf("offcpu_kernel_stack:\n");
				for(int i=0 ; i<t_count ; i++){
					print_stack(e->kstack[i]);
				}
			}
		}
	}else if(e->flag == 0){
		time = (e->oncpu_time - e->offcpu_time)*1.0/1000000000.0;
		printf("flag:%d  pid:%d  comm:%s  offcpu_id:%d  offcpu_time(ns):%llu  oncpu_id :%d  oncpu_time(ns) :%llu  time(s):%lf\n",
		e->flag,e->pid,e->comm,e->offcpu_id,e->offcpu_time,e->oncpu_id,e->oncpu_time,time);
	
		if(env.enable_cs){
			printf("pid:%d,comm:%s,prio:%d -> pid:%d,comm:%s,prio:%d\n", e->n_pid,e->n_comm,e->n_prio,e->pid,e->comm,e->prio);
		}
	}

	printf("\n");
    
	return 0;
}
	

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct lifecycle_image_bpf *skel;
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
	skel = lifecycle_image_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_pid = env.pid;
	skel->rodata->target_cpu_id = env.cpu_id;

	/* 加载并验证BPF程序 */
	err = lifecycle_image_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	/* 附加跟踪点处理程序 */
	err = lifecycle_image_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	/* 设置环形缓冲区轮询 */
	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
	rb = ring_buffer__new(bpf_map__fd(skel->maps.cpu_rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	/* 处理事件 */
	while (!exiting) {
		//ring_buffer__poll(),轮询打开ringbuf缓冲区。如果有事件，handle_event函数会执行
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
	
/* 卸载BPF程序 */
cleanup:
	ring_buffer__free(rb);
	lifecycle_image_bpf__destroy(skel);
	ksyms__free(ksyms);
	
	return err < 0 ? -err : 0;
}
