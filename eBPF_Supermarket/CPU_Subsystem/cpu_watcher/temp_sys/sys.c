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
#include "sys.skel.h"
#include "sys.h"
#include <linux/perf_event.h>
#include <asm/unistd.h>



#define warn(...) fprintf(stderr, __VA_ARGS__)
typedef long long unsigned int u64;
typedef unsigned int u32;
static volatile bool exiting = false;//全局变量，表示程序是否正在退出

struct sys_bpf *skel;//用于自行加载和运行BPF程序的结构体，由libbpf自动生成并提供与之关联的各种功能接口；

unsigned long ktTime = 0;
unsigned long utTime = 0;
u64 tick_user = 0;//初始化sys;

static struct env {
	int time;
	bool enable_proc;
	bool libbpf_sar;
	bool cs_delay;
	int freq;
} env = {
	.time = 0,
	.enable_proc = false,
	.libbpf_sar = false,
	.cs_delay = false,
	.freq = 99,
};
static void sig_handler(int sig)//信号处理函数
{
	exiting = true;
}//正在退出程序；
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int nr_cpus;
static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
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

static int print_all()
{

	/*kthread*/
	int key_kthread = 0;
	int err_kthread, fd_kthread = bpf_map__fd(skel->maps.kt_LastTime);
	unsigned long  _ktTime=0; 
	_ktTime = ktTime;
	err_kthread = bpf_map_lookup_elem(fd_kthread, &key_kthread,&ktTime);
	if (err_kthread < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err_kthread);
		return -1;
	}
	unsigned long dtaKT = ktTime -_ktTime;

	/*Uthread*/
	int key_uthread = 0;
	int err_uthread, fd_uthread = bpf_map__fd(skel->maps.ut_LastTime);
	unsigned long  _utTime=0; 
	_utTime = utTime;
	err_uthread = bpf_map_lookup_elem(fd_uthread, &key_uthread,&utTime);
	if (err_uthread < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err_uthread);
		return -1;
	}
	unsigned long dtaUT = utTime -_utTime;

	/*sys*/
	int key_sys = 0;// 设置要查找的键值为1
	int err_sys, fd_sys = bpf_map__fd(skel->maps.tick_user);// 获取映射文件描述符
	u64 __tick_user =0 ;// 用于存储从映射中查找到的值
    __tick_user = tick_user;
	err_sys = bpf_map_lookup_elem(fd_sys, &key_sys, &tick_user); // 从映射中查找键为1的值
	if (err_sys < 0) {//没找到
		fprintf(stderr, "failed to lookup infos of sys: %d\n", err_sys);
		return -1;
	}
	u64 dtaTickUser = tick_user - __tick_user;
	u64 dtaUTRaw = dtaTickUser * 1000000000; 
    u64 dtaSysc = dtaUT - dtaUTRaw ;
	u64 dtaSys = dtaKT + dtaSysc ;

	if(env.enable_proc){
		//判断打印：
		time_t now = time(NULL);// 获取当前时间
		struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
		//printf("%02d:%02d:%02d %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec,tick_user,__tick_user,dtaTickUser,dtaUTRaw,dtaUT/ 1000000,dtaKT/ 1000000,dtaSysc/ 1000000,dtaSys / 1000000);
		printf("%02d:%02d:%02d %8llu\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec,dtaSys / 1000000);
	}
	else{
		env.enable_proc = true;
	}

    return 0;
}


int main(int argc, char **argv)
{
	int err;//用于存储错误码
	const char* symbol_name = "total_forks";

	struct bpf_link *links[MAX_CPU_NR] = {};

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);
	/* 更干净地处理Ctrl-C
	   SIGINT：由Interrupt Key产生，通常是CTRL+C或者DELETE。发送给所有ForeGround Group的进程
       SIGTERM：请求中止进程，kill命令发送
	*/
	signal(SIGINT, sig_handler);		//注册一个信号处理函数 sig_handler，用于处理 Ctrl-C 信号（SIGINT）
	signal(SIGTERM, sig_handler);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	/* 打开BPF应用程序 */
	skel = sys_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->forks_addr = (u64)find_ksym(symbol_name);
	/* 加载并验证BPF程序 */
	err = sys_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	/*perf_event加载*/
	err = open_and_attach_perf_event(env.freq, skel->progs.tick_update, links);
	if (err)
		goto cleanup;


	/* 附加跟踪点处理程序 */
	err = sys_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	printf("Tracing for Data's... Ctrl-C to end\n");

    // rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), print_all, NULL, NULL);
	// if (!rb) {
	// 	err = -1;
	// 	fprintf(stderr, "Failed to create ring buffer\n");
	// 	goto cleanup;
	// }

	//printf("  time    proc/s  cswch/s  runqlen  idle/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms  BpfCnt\n");
	//printf("  time   	t_ur  	_tur  	TU  	UTR  	UT  	KT  	Sysc   	Sys\n");
	printf("  time    	Sys\n");
	/* 处理事件 */
	while (!exiting) {
		sleep(1);
        err = print_all();
		//err = ring_buffer__poll(rb, 1000 /* timeout, s */);
		
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
    /* Clean up */
	//ring_buffer__free(rb);//释放环形缓冲区
	sys_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}
