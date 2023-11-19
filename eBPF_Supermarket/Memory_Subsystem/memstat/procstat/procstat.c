// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "procstat.h"
#include "procstat.skel.h"
#include <sys/select.h>

// 用于存储命令行参数的结构体
static struct env {
    long choose_pid; // 选择的进程ID
    long time_s;     // 延时时间（单位：毫秒）
    long rss;        // 是否显示进程页面信息
} env; 

// 命令行选项
static const struct argp_option opts[] = {
    { "choose_pid", 'p', "PID", 0, "选择特定进程显示信息。" },
    { "time_s", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
    { "Rss", 'r', NULL, 0, "显示进程页面信息。"},
};

// 命令行参数解析函数
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'p':
            env.choose_pid = strtol(arg, NULL, 10);
            break;
        case 't':
			env.time_s = strtol(arg, NULL, 10);
            if(env.time_s) alarm(env.time_s);
                break;
		case 'r':
			env.rss = true;
            break;
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

// 命令行解析器
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
};

// libbpf输出回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

// 信号处理函数，处理Ctrl-C
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

// 毫秒级睡眠函数
static void msleep(long ms) {
    struct timeval tval;
    tval.tv_sec = ms / 1000;
    tval.tv_usec = (ms * 1000) % 1000000;
    select(0, NULL, NULL, NULL, &tval);
}

// 处理BPF事件的回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if(env.choose_pid) {
        if(e->pid == env.choose_pid) {
            if(env.rss) {
                printf("%-8s %-8d %-8ld %-8ld %-8ld %-8lld %-8lld\n", ts, e->pid, e->vsize, e->Vdata, e->Vstk, e->VPTE, e->vswap);
            } else {
                printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n", ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
            }
        }
    } else {
        if(env.rss) {
            printf("%-8s %-8d %-8ld %-8ld %-8ld %-8lld %-8lld\n", ts, e->pid, e->vsize, e->Vdata, e->Vstk, e->VPTE, e->vswap);
        } else {
            printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n", ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
        }
    }

    // 根据延时时间休眠
    /*
    if(env.time_s != NULL) {
		msleep(env.time_s);
	}
	else {
		msleep(1000);
	}
	return 0;
    */	
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct procstat_bpf *skel;
    int err;

    // 解析命令行参数
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    // 设置libbpf的严格模式和调试信息回调
    /* Set up libbpf errors and debug info callback */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // 注册信号处理函数
    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);

    // 打开BPF程序并加载验证BPF程序
    /* Load and verify BPF application */
    skel = procstat_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 加载并验证BPF程序
    /* Load & verify BPF programs */
    err = procstat_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 注册BPF程序的tracepoints
    /* Attach tracepoints */
    err = procstat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 创建用于处理事件的环形缓冲区
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 打印表头
    /* Process events */
    if(env.rss) {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "VMSIZE", "VMDATA", "VMSTK", "VMPTE", "VMSWAP");
    } else {        
        printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
    }

    // 处理事件
	while (!exiting) {
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

cleanup:
    // 清理并释放资源
    /* Clean up */
    ring_buffer__free(rb);
    procstat_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
