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
// author: albert_xuu@163.com 

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <argp.h>
#include <errno.h>
#include <time.h>
#include "migrate_image.skel.h"
#include "migrate_image.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile bool exiting = false;
struct migrate_image_bpf *skel;
// static struct env {
// 	int pid;
// 	int time;
// 	int cpu_id;
// 	int stack_count;
// 	bool set_stack;
// 	bool enable_cs;
// } env = {
// 	.pid = 0,
// 	.time = 0,
// 	.cpu_id = 0,
// 	.stack_count = 0,
// 	.set_stack = false,
// 	.enable_cs = false,
// };

static struct ksyms *ksyms = NULL;

const char argp_program_doc[] ="Trace process to get process life cycle image.\n";

// static const struct argp_option opts[] = {
// 	{ "pid", 'p', "PID", 0, "Process ID to trace" },
// 	{ "cpuid", 'C', "CPUID", 0, "Set For Tracing Process 0(other processes don't need to set this parameter)" },
// 	{ "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
// 	{ "cs-reason", 'r', NULL, 0, "Process context switch reasons annotation" },
// 	{ "stack", 's', "STACK-COUNT", 0, "The number of kernel stacks printed when the process is under the CPU" },
// 	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
// 	{},
// };

// static error_t parse_arg(int key, char *arg, struct argp_state *state)
// {
// 	long pid;
// 	long cpu_id;
// 	long stack;
// 	switch (key) {
// 		case 'p':
// 				errno = 0;
// 				pid = strtol(arg, NULL, 10);
// 				if (errno || pid < 0) {
// 					warn("Invalid PID: %s\n", arg);
// 					// 调用argp_usage函数，用于打印用法信息并退出程序
// 					argp_usage(state);
// 				}
// 				env.pid = pid;
// 				break;
// 		case 'C':
// 				cpu_id = strtol(arg, NULL, 10);
// 				if(cpu_id < 0){
// 					warn("Invalid CPUID: %s\n", arg);
// 					argp_usage(state);
// 				}
// 				env.cpu_id = cpu_id;
// 				break;
// 		case 't':
// 				env.time = strtol(arg, NULL, 10);
// 				if(env.time) alarm(env.time);
// 				break;
// 		case 'r':
// 				env.enable_cs = true;
// 				break;
// 		case 's':
// 				stack = strtol(arg, NULL, 10);
// 				if (stack < 0) {
// 					warn("Invalid STACK-COUNT: %s\n", arg);
// 					// 调用argp_usage函数，用于打印用法信息并退出程序
// 					argp_usage(state);
// 				}
// 				env.stack_count = stack;
// 				env.set_stack = true;
// 				break;
// 		case 'h':
// 				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
// 				break;
// 		default:
// 				return ARGP_ERR_UNKNOWN;
// 	}
	
// 	return 0;
// }

static void sig_handler(int sig)
{
	exiting = true;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int migrate_print(){
	time_t now = time(NULL);// 获取当前时间
	struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
	printf("\nTime: %02d:%02d:%02d\n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
	printf("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	int err,migrate_fd =bpf_map__fd(skel->maps.migrate),migrate_info_fd =bpf_map__fd(skel->maps.migrate_info);

	pid_t lookup_key = -1 ,next_key;
	struct migrate_event migrate_event;
	while(!bpf_map_get_next_key(migrate_fd, &lookup_key, &next_key)){//遍历打印hash map
		err = bpf_map_lookup_elem(migrate_fd,&next_key,&migrate_event);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos2: %d\n", err);
			return -1;
		}
		if(migrate_event.count <= migrate_event.rear) {
			lookup_key = next_key;
			continue;
		}
		u64 last_time_stamp = 0;
		printf("\npid:%d\tprio:%d\tcount:%d\trear:%d\n",migrate_event.pid,migrate_event.prio,migrate_event.count,migrate_event.rear);
		printf("---------------------------------------------------------------------------------\n");
		for(int i=migrate_event.rear;i<=migrate_event.count;i++){
			struct per_migrate migrate_info;
			struct minfo_key mkey;	
			mkey.pid = migrate_event.pid;
			mkey.count = i;
			err = bpf_map_lookup_elem(migrate_info_fd,&mkey,&migrate_info);
			if (err < 0) {
				fprintf(stderr, "failed to lookup infos err %d mkey_pid: %d mkey_count: %d\n", err,mkey.pid,i);
				continue;
			}
			printf("time_stamp:%llu\t%d->%d \t PROC_LOAD:%llu \t PROC_UTIL:%llu\t",
					migrate_info.time,migrate_info.orig_cpu,migrate_info.dest_cpu,migrate_info.pload_avg,migrate_info.putil_avg);
			printf("CPU_LOAD: %ld \t Cpu_Capacity:[%ld:%ld] \t ",migrate_info.cpu_load_avg,migrate_info.cpu_capacity,migrate_info.cpu_capacity_orig);
			printf("mmem_usage:%llu kb \t\t read:%llu kb \t\t wite:%llu kb \t\t context_switch:%llu\t",
					migrate_info.mem_usage/1024,migrate_info.read_bytes/1024,migrate_info.write_bytes/1024,
        			migrate_info.context_switches);

			if(i==migrate_event.rear && last_time_stamp == 0) {
				last_time_stamp = migrate_info.time;
				printf("delay: /\n");
			}else{
				printf("delay: %d us\n",(migrate_info.time - last_time_stamp)/1000);
				last_time_stamp = migrate_info.time;
			}
			bpf_map_delete_elem(migrate_info_fd,&mkey);//删除已经打印了的数据

		}
		migrate_event.rear = migrate_event.count + 1;
		bpf_map_update_elem(migrate_fd,&next_key,&migrate_event,BPF_ANY);
		lookup_key = next_key;
	}
	printf("---------------------------------------------------------------------------------\n\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;
	// static const struct argp argp = {
	// 	.options = opts,
	// 	.parser = parse_arg,
	// 	.doc = argp_program_doc,
	// };

	// err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	// if (err)
	// 	return err;


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
	skel = migrate_image_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* 加载并验证BPF程序 */
	err = migrate_image_bpf__load(skel);
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
	err = migrate_image_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	/* 处理事件 */
	while (!exiting) {
		sleep(1);
		err = migrate_print();
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
            printf("Error: %d\n", err);
			break;
		}	
	}
	
/* 卸载BPF程序 */
cleanup:
	// ring_buffer__free(rb);
	migrate_image_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
