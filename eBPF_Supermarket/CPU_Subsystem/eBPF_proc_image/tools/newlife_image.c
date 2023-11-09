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
// user-mode code for the new life image

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <argp.h>
#include <errno.h>
#include "newlife_image.skel.h"
#include "newlife_image.h"

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

static volatile bool exiting = false;
static const char object[] = "/usr/lib/x86_64-linux-gnu/libc.so.6";
static struct env {
	int pid;
	int time;
	bool enable_fork;
	bool enable_vfork;
	bool enable_newthread;
} env = {
	.pid = 0,
	.time = 0,
	.enable_fork = false,
	.enable_vfork = false,
	.enable_newthread = false,
};

const char argp_program_doc[] ="Trace process to get newlife image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "process ID to trace" },
	{ "time", 't', "TIME-SEC", 0, "max running time(0 for infinite)" },
	{ "fork", 'f', NULL, 0, "the child process image of fork" },
	{ "vfork", 'F', NULL, 0, "the child process image of vfork" },
	{ "newthread", 'T', NULL, 0, "the new thread image" },
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
				if (errno || pid <= 0) {
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
		case 'f':
				env.enable_fork = true;
				break;
		case 'F':
				env.enable_vfork = true;
				break;
		case 'T':
				env.enable_newthread = true;
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

static int handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct newlife_event *e = data;
	const char *c;
	double exist_time;

	switch (e->flag) {
		case 1:
				c = "fork";
				break;
		case 2:
				c= "vfork";
				break;
		case 3:
				c= "newthread";
				break;
		default:
                return 0;
	}

	if(e->exit == 0){
		printf("%s_pid:%d  start(ns):%llu\n",c,e->newlife_pid,e->start);
	}else{
		exist_time = (e->exit - e->start)*1.0/1000.0;
		printf("%s_pid:%d  start(ns):%llu  exit(ns):%llu  exist_time(us):%lf\n",
				c,e->newlife_pid,e->start,e->exit,exist_time);
	}

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int attach(struct newlife_image_bpf *skel)
{
	int err;

	ATTACH_URETPROBE_CHECKED(skel,fork,fork_exit);
	ATTACH_URETPROBE_CHECKED(skel,vfork,vfork_exit);

// libbpf: elf: ambiguous match for 'pthread_create', 'pthread_create' in '/usr/lib/x86_64-linux-gnu/libc.so.6'
// 但其实libc.so.6库中是存在 pthread_create ，nm -D /usr/lib/x86_64-linux-gnu/libc.so.6 | grep pthread_create：
// 0000000000094cc0 T pthread_create@GLIBC_2.2.5 
// 0000000000094cc0 T pthread_create@@GLIBC_2.34
// 可以发现libc.so.6库中存在两个pthread_create，这也就是导致出现 ambiguous match 的原因，经查阅官方库函数也证实了该问题（bpftrace具有处理该问题的能力）
// 在Ubuntu22.04.1中 fork 和 vfork 调用的都是clone系统调用，而 pthread_create 调用的是 clone3 系统调用，因此暂用 clone3 监控新线程
//	ATTACH_UPROBE_CHECKED(skel,pthread_create,pthread_create_enter);
//	ATTACH_URETPROBE_CHECKED(skel,pthread_create,pthread_create_exit);

	err = newlife_image_bpf__attach(skel);
	CHECK_ERR(err, "Failed to attach BPF skeleton");

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct newlife_image_bpf *skel;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if(env.enable_fork == false && env.enable_vfork == false && env.enable_newthread == false)
	{
		env.enable_fork = true;
		env.enable_vfork = true;
		env.enable_newthread = true;
	}

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
	skel = newlife_image_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_pid = env.pid;
	skel->rodata->enable_fork = env.enable_fork;
	skel->rodata->enable_vfork = env.enable_vfork;
	skel->rodata->enable_newthread = env.enable_newthread;

	/* 加载并验证BPF程序 */
	err = newlife_image_bpf__load(skel);
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
	
	/* 设置环形缓冲区轮询 */
	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
	rb = ring_buffer__new(bpf_map__fd(skel->maps.newlife_rb), handle_event, NULL, NULL);
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
	newlife_image_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}
