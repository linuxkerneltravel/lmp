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
// user-mode code for the process lock image

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <argp.h>
#include <errno.h>
#include "lock_image.skel.h"
#include "lock_image.h"

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
	bool enable_u_mutex;
	bool enable_k_mutex;
	bool enable_u_rwlock_rd;
	bool enable_u_rwlock_wr;
} env = {
	.pid = 0,
	.time = 0,
	.enable_u_mutex = false,
	.enable_k_mutex = false,
	.enable_u_rwlock_rd = false,
	.enable_u_rwlock_wr = false,
};

const char argp_program_doc[] ="Trace process to get lock image.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "process ID to trace" },
	{ "time", 't', "TIME-SEC", 0, "max running time(0 for infinite)" },
	{ "user-mutex", 'm', NULL, 0, "process user mutex image" },
	{ "kernel-mutex", 'M', NULL, 0, "process kernel mutex image" },
	{ "user-rwlock-rd", 'r', NULL, 0, "process user rwlock image in read mode" },
	{ "user-rwlock-wr", 'w', NULL, 0, "process user rwlock image in write mode" },
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
	const struct lock_event *e = data;
	const char *c;
	double acq_time,hold_time;

	switch (e->type) {
		case 1:
			c = "u_mutex";
			break;
		case 2:
			c = "k_mutex";
			break;
		case 3:
			c = "u_rwlock_rd";
			break;
		case 4:
			c = "u_rwlock_wr";
			break;
		default:
			return 0;
	}

	if(e->unlock_time!=0)
	{
		acq_time = (e->lock_time - e->lock_acq_time)*1.0/1000.0;
		hold_time = (e->unlock_time - e->lock_time)*1.0/1000.0;
	}else if(e->lock_time!=0){
		acq_time = (e->lock_time - e->lock_acq_time)*1.0/1000.0;
		hold_time = 0;
	}else{
		acq_time = 0;
		hold_time = 0;
	}

	printf("pid:%d  comm:%s  %s_ptr:%llu\n", e->pid,e->comm,c,e->lock_ptr);
	printf("lock_acq_time(ns):%-15llu lock_time(ns):%-15llu unlock_time(ns):%-15llu acq_time(us):%-15.3lf hold_time(us):%-15.3lf\n",
		e->lock_acq_time,e->lock_time,e->unlock_time,acq_time,hold_time);
    
	printf("\n");
	
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
	CHECK_ERR(err, "Failed to attach BPF skeleton");
	
	return 0;

}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct lock_image_bpf *skel;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
    
	if(env.enable_u_mutex == false && env.enable_k_mutex == false && env.enable_u_rwlock_rd == false && env.enable_u_rwlock_wr == false)
	{
		env.enable_u_mutex = true;
		env.enable_k_mutex = true;
		env.enable_u_rwlock_rd = true;
		env.enable_u_rwlock_wr = true;
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
	skel = lock_image_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_pid = env.pid;
	skel->rodata->enable_u_mutex = env.enable_u_mutex;
	skel->rodata->enable_k_mutex = env.enable_k_mutex;
	skel->rodata->enable_u_rwlock_rd = env.enable_u_rwlock_rd;
	skel->rodata->enable_u_rwlock_wr = env.enable_u_rwlock_wr;

	/* 加载并验证BPF程序 */
	err = lock_image_bpf__load(skel);
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
	rb = ring_buffer__new(bpf_map__fd(skel->maps.lock_rb), handle_event, NULL, NULL);
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
	lock_image_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}
