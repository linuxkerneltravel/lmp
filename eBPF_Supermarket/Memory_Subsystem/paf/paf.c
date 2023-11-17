// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "paf.h"
#include "paf.skel.h"
#include <sys/select.h>

// 存储命令行参数的结构体
static struct env {
    long choose_pid; // 选择的进程ID
    long time_s;     // 延时时间（单位：毫秒）
    long rss;        // 是否显示进程页面信息
} env;

// 命令行选项定义
static const struct argp_option opts[] = {
    { "choose_pid", 'p', "PID", 0, "选择特定进程显示信息。" },
    { "time_s", 't', "MS", 0, "延时打印时间，单位：毫秒" },
    { "Rss", 'r', NULL, 0, "显示进程页面信息。"},
};

// 命令行参数解析函数
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'p':
            env.choose_pid = strtol(arg, NULL, 10);
            break;
        case 't':
            env.time_s = strtol(arg, NULL, 10);
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
static volatile bool exiting;
static void sig_handler(int sig) {
    exiting = true;
}

// 毫秒级别的睡眠函数
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

    // 根据命令行参数选择要显示的信息
    if (env.choose_pid) {
        if (e->pid == env.choose_pid) {
            // 根据是否显示进程页面信息选择输出格式
            if (env.rss) {
                // 显示进程页面信息
                printf("%-8s %-8lu %-8lu %-8lu %-8lu %-8x\n",
                       ts, e->min, e->low, e->high, e->present, e->flag);
            } else {
                // 显示进程内存信息
                printf("%-8s %-8lu %-8lu %-8lu %-8lu\n",
                       ts, e->min, e->low, e->high, e->present);
            }
        }
    } else {
        // 根据是否显示进程页面信息选择输出格式
        if (env.rss) {
            // 显示进程页面信息
            printf("%-8s %-8lu %-8lu %-8lu %-8lu %-8x\n",
                   ts, e->min, e->low, e->high, e->present, e->flag);
        } else {
            // 显示进程内存信息
            printf("%-8s %-8lu %-8lu %-8lu %-8lu\n",
                   ts, e->min, e->low, e->high, e->present);
        }
    }

    // 根据延时时间休眠
    if (env.time_s) {
        msleep(env.time_s);
    } else {
        msleep(1000);
    }
    return 0;
}

// 主函数
int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct paf_bpf *skel;
    int err;

    // 解析命令行参数
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    // 设置libbpf严格模式
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // 设置libbpf错误输出回调函数
    libbpf_set_print(libbpf_print_fn);

    // 设置Ctrl-C的处理函数
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 打开BPF程序
    skel = paf_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 加载BPF程序
    err = paf_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 关联BPF程序和事件
    err = paf_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 创建ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 打印表头
    if (env.rss) {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "MIN", "LOW", "HIGH", "PRESENT", "FLAG");
    } else {
        printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "MIN", "LOW", "HIGH", "PRESENT");
    }

    // 处理事件
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* 超时时间，单位：毫秒 */);
        // Ctrl-C会产生-EINTR错误
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
    // 释放资源
    ring_buffer__free(rb);
    paf_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}