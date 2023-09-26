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
// user-mode code for libbpf sar

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <argp.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "libbpf_sar.skel.h"
#include "libbpf_sar.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
typedef long long unsigned int u64;

static volatile bool exiting = false;

// 长期保存的数值
static u64 proc = 0;

static u64 sum[10] = {};

static int line = 0;

// sar 工具的参数设置
static struct env {
    int time;
	bool enable_proc;
} env = {
    .time = 0,
	.enable_proc = false,
};

const char argp_program_doc[] ="libbpf_sar is a program that simulates sar constructed by libbpf for dynamic CPU indicator monitoring.\n";

static const struct argp_option opts[] = {
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
		case 't':
                env.time = strtol(arg, NULL, 10);
                if(env.time) alarm(env.time);
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

static int print_countMap(struct bpf_map *map)
{
	int key = 1;
	int err, fd = bpf_map__fd(map);
	unsigned long total_forks;

	err = bpf_map_lookup_elem(fd, &key, &total_forks);
	if (err < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err);
		return -1;
	}
	
	if(env.enable_proc){
		u64 proc_s;
		time_t now = time(NULL);
		struct tm *localTime = localtime(&now);
		
		line++;
		proc_s = total_forks-proc;
		sum[0] += proc_s;
		proc_s = sum[0]/line;
		proc = total_forks;

		printf("%02d:%02d:%02d  %6lld\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec, proc_s);
	}else{				// 第一次的数据无法做差，所以不予输出
		proc = total_forks;
		env.enable_proc = true;
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 函数用于从/proc/kallsyms文件中搜索内核符号
const char* find_ksym(const char* symbol_name) {
    // 打开/proc/kallsyms文件
    FILE* file = fopen("/proc/kallsyms", "r");
    if (!file) {
        perror("Error opening /proc/kallsyms");
        return NULL;
    }

    char line[256];
    const char* addr = NULL;

    // 逐行读取文件内容
    while (fgets(line, sizeof(line), file)) {
        // 检查是否包含符号名称
        if (strstr(line, symbol_name)) {
            // 分割行，获取地址部分
            char* token = strtok(line, " ");
            addr = token;
            break;
        }
    }

    fclose(file);
    return addr;
}

int main(int argc, char **argv)
{
	struct libbpf_sar_bpf *skel;
	int err;
	const char* symbol_name = "total_forks";
	const char* addr;
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
	signal(SIGINT, sig_handler);		//signal设置某一信号的对应动作
	signal(SIGTERM, sig_handler);

	/* 打开BPF应用程序 */
	skel = libbpf_sar_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	addr = find_ksym(symbol_name);
    if (addr) {
        // 将地址转换为长整数，并存储在BPF程序的symAddr数组中
        skel->rodata->forks_addr = (u64)strtoull(addr, NULL, 16);
    } else {
        printf("Symbol not found\n");
    }

	/* 加载并验证BPF程序 */
	err = libbpf_sar_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	/* 附加跟踪点处理程序 */
	err = libbpf_sar_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	printf("Tracing for Data's... Ctrl-C to end\n");
	printf("  time    proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms  BpfCnt\n");

	/* 处理事件 */
	while (!exiting) {
		sleep(1);
		
		err = print_countMap(skel->maps.countMap);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			break;
		}
	}
	
/* 卸载BPF程序 */
cleanup:
	libbpf_sar_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}