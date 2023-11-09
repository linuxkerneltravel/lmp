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

static volatile bool exiting = false;//全局变量，表示程序是否正在退出

// 长期保存的数值
static u64 proc = 0;
static u64 sched =0;
static u64 sched2 =0;

static u64 sum[10] = {};//用于存储要输出的各个数据结果；

static int line = 0;

// sar 工具的参数设置
static struct env {
	int time;
	bool enable_proc;
	//bool enable_sched_prwitch;
} env = {
	.time = 0,
	.enable_proc = false,
	//.enable_sched_prwitch = false,
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
}//正在退出程序；

static int print_countMap(struct bpf_map *map)
{
	
	
	int key = 0;// 设置要查找的键值为1
	int err, fd = bpf_map__fd(map);// 获取映射文件描述符
	u64 total_forks;// 用于存储从映射中查找到的值
	err = bpf_map_lookup_elem(fd, &key, &total_forks); // 从映射中查找键为1的值
	if (err < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of total_forks: %d\n", err);
		return -1;
	}
	
	
	key = 1;// 设置要查找的键值为1
	u64 sched_total;// 用于存储从映射中查找到的值
	//int err, fd = bpf_map__fd(map);// 获取映射文件描述符
	err = bpf_map_lookup_elem(fd, &key, &sched_total); // 从映射中查找键为1的值
	if (err < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of sched_total: %d\n", err);
		return -1;
	}

	
	key=2;
	int runqlen;// 用于存储从映射中查找到的值
	err = bpf_map_lookup_elem(fd, &key, &runqlen); // 从映射中查找键为1的值
	if (err < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of runqlen: %d\n", err);
		return -1;
	}
	

	//proc:
	u64 proc_s;
	proc_s = total_forks-proc;
	proc = total_forks;//统计差值；
	
	
	//cswch:
	u64 sched_pr;
	sched_pr= sched_total - sched;//计算差值;
	sched = sched_total;

	//runqlen:
	/*nothing*/

	//判断打印：
	if(env.enable_proc){
		time_t now = time(NULL);// 获取当前时间
		struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
		printf("%02d:%02d:%02d  %6lld  %6lld  %6d\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec,proc_s,sched_pr,runqlen);
	}else{				// 第一次的数据无法做差，所以不予输出
		env.enable_proc = true;
	}
	

	/*
	//只打印cswch/s 
	if(env.enable_sched_prwitch){
		u64 sched_pr;//要输出的进程切换次数
		time_t now = time(NULL);// 获取当前时间
		struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
		
		sched_pr= sched_total - sched;//计算差值;
		sched = sched_total;


		printf("%02d:%02d:%02d  %6lld\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec, sched_pr);
	}else{				// 第一次的数据无法做差，所以不予输出
		sched = sched_total;//全局变量proc
		env.enable_sched_prwitch = true;
	}
	*/
	
	//只打印proc
	/*
	if(env.enable_proc){
		u64 proc_s;
		time_t now = time(NULL);// 获取当前时间
		struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
		
		line++;
		proc_s = total_forks-proc;
		sum[0] += proc_s;
		proc_s = sum[0]/line;
		proc = total_forks;

		printf("%02d:%02d:%02d  %6lld\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec, proc_s);
	}else{				// 第一次的数据无法做差，所以不予输出
		proc = total_forks;//全局变量proc
		env.enable_proc = true;
	}
	*/

	//同时打印proc、cswch/s 失败
	/*if(env.enable_sched_prwitch||env.enable_proc){
		u64 proc_pr;//要输出的新创建的进程数
		u64 sched_pr;//要输出的进程切换次数
		time_t now = time(NULL);// 获取当前时间
		struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
		

		line++;
		proc_pr = proc_total-proc;
		sum[0] += proc_pr;
		proc_pr = sum[0]/line;
		proc = proc_total;

		sched_pr= sched_total - sched;//计算差值;
		sched = sched_total;

		printf("%02d:%02d:%02d  %6lld  %6lld\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec, proc_pr,sched_pr);
	}else{				// 第一次的数据无法做差，所以不予输出
		proc = proc_total;//全局变量proc
		env.enable_proc = true;

		sched = sched_total;//全局变量proc
		env.enable_sched_prwitch = true;
	}
	*/
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// 根据符号名称从/proc/kallsyms文件中搜索对应符号地址
u64 find_ksym(const char* target_symbol) {
    FILE *file = fopen("/proc/kallsyms", "r");
    if (file == NULL) {
        perror("Failed to open /proc/kallsyms");
        return 1;
    }

    char symbol_name[99];
    u64 symbol_address = 0;

    while (fscanf(file, "%llx %*c %s\n", &symbol_address, symbol_name) != EOF) {
        if (strcmp(symbol_name, target_symbol) == 0) {
            break;
        }
    }

    fclose(file);

    return symbol_address;
}

int main(int argc, char **argv)
{
	struct libbpf_sar_bpf *skel;
	int err;
	const char* symbol_name = "total_forks";
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
	signal(SIGALRM, sig_handler);

	/* 打开BPF应用程序 */
	skel = libbpf_sar_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->forks_addr = (u64)find_ksym(symbol_name);

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

	//printf("  time    proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms  BpfCnt\n");
	printf("  time   proc/s  cswch/s  runqlen\n");
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
