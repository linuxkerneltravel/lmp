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
// used to control the execution of proc_image tool
#include <stdio.h>
#include <stdbool.h>
#include <argp.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include "proc_image.h"
#include "hashmap.h"
#include "helpers.h"

static struct env {
    // 1代表activate；2代表deactivate；3代表finish
    int usemode;
    int pid;
	int tgid;
    int cpu_id;
    int time;
    int syscalls;
    bool enable_myproc;
    bool output_resourse;
	bool output_schedule;
    bool create_thread;
	bool exit_thread;
    bool enable_resource;
    bool first_rsc;
    bool enable_cpu;
    bool enable_keytime;
    bool enable_lock;
    bool enable_syscall;
    bool enable_schedule;
}  env = {
    .usemode = 0,
    .pid = -1,
	.tgid = -1,
    .cpu_id = -1,
    .time = 0,
    .syscalls = 0,
	.enable_myproc = false,
	.output_resourse = false,
	.output_schedule = false,
	.create_thread = false,
	.exit_thread = false,
    .enable_resource = false,
	.first_rsc = true,
    .enable_cpu = false,
    .enable_keytime = false,
    .enable_lock = false,
    .enable_syscall = false,
    .enable_schedule = false,
};

const char argp_program_doc[] ="Trace process to get process image.\n";

static const struct argp_option opts[] = {
    { "activate", 'a', NULL, 0, "Set startup policy of proc_image tool" },
    { "deactivate", 'd', NULL, 0, "Initialize to the original deactivated state" },
    { "finish", 'f', NULL, 0, "Finish to run eBPF tool" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
    { "tgid", 'P', "TGID", 0, "Thread group to trace" },
    { "cpuid", 'c', "CPUID", 0, "Set For Tracing  per-CPU Process(other processes don't need to set this parameter)" },
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
    { "myproc", 'm', NULL, 0, "Trace the process of the tool itself (not tracked by default)" },
    { "resource", 'r', NULL, 0, "Collects resource usage information about processes" },
    { "keytime", 'k', "KEYTIME", 0, "Collects keytime information about processes(0:except CPU kt_info,1:all kt_info,any 0 or 1 when deactivated)" },
    { "lock", 'l', NULL, 0, "Collects lock information about processes" },
    { "syscall", 's', "SYSCALLS", 0, "Collects syscall sequence (1~50) information about processes(any 1~50 when deactivated)" },
    { "schedule", 'S', NULL, 0, "Collects schedule information about processes (trace tool process)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    long pid;
	long tgid;
	long cpu_id;
    long syscalls;
    long enable_cpu;
    switch (key) {
        case 'a':
            env.usemode = 1;
            break;
        case 'd':
            env.usemode = 2;
            break;
        case 'f':
            env.usemode = 3;
            break;
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
        case 'P':
				errno = 0;
				tgid = strtol(arg, NULL, 10);
				if (errno || tgid < 0) {
					warn("Invalid TGID: %s\n", arg);
					// 调用argp_usage函数，用于打印用法信息并退出程序
					argp_usage(state);
				}
				env.tgid = tgid;
				break;
		case 'c':
				errno = 0;
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
		case 'm':
				env.enable_myproc = true;
				break;
		case 'r':
				env.enable_resource = true;
				break;
        case 'k':
                enable_cpu = strtol(arg, NULL, 10);
                if(enable_cpu<0 || enable_cpu>1){
					warn("Invalid KEYTIME: %s\n", arg);
					argp_usage(state);
				}
                env.enable_cpu = enable_cpu;
                env.enable_keytime = true;
                break;
        case 'l':
                env.enable_lock = true;
                break;
        case 's':
                syscalls = strtol(arg, NULL, 10);
				if(syscalls<=0 || syscalls>50){
					warn("Invalid SYSCALLS: %s\n", arg);
					argp_usage(state);
				}
				env.syscalls = syscalls;
				env.enable_syscall = true;
                break;
        case 'S':
                env.enable_schedule = true;
                break;
        case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
        default:
				return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int deactivate_mode(){
    int err;

    if(env.enable_resource){
        struct rsc_ctrl rsc_ctrl = {false,-1,-1,false,-1};
        err = update_rsc_ctrl_map(rsc_ctrl);
        if(err < 0) return err;
    }

    if(env.enable_keytime){
        struct kt_ctrl kt_ctrl = {false,false,false,-1,-1};
        err = update_kt_ctrl_map(kt_ctrl);
        if(err < 0) return err;
    }

    if(env.enable_lock){
        struct lock_ctrl lock_ctrl = {false,false,-1,-1};
        err = update_lock_ctrl_map(lock_ctrl);
        if(err < 0) return err;
    }

    if(env.enable_syscall){
        struct sc_ctrl sc_ctrl = {false,false,-1,-1,0};
        err = update_sc_ctrl_map(sc_ctrl);
        if(err < 0) return err;
    }

    if(env.enable_schedule){
        struct sched_ctrl sched_ctrl = {false,-1,-1,-1};
        err = update_sched_ctrl_map(sched_ctrl);
        if(err < 0) return err;
    }

    return 0;
}

static void sig_handler(int signo)
{
	deactivate_mode();
}

int main(int argc, char **argv)
{
    int err;
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

    signal(SIGALRM,sig_handler);
	signal(SIGINT,sig_handler);
	signal(SIGTERM,sig_handler);

    if(env.usemode == 1){                   // activate mode
        if(env.enable_resource){
            struct rsc_ctrl rsc_ctrl = {true, env.pid, env.cpu_id, env.enable_myproc, env.tgid};
            err = update_rsc_ctrl_map(rsc_ctrl);
            if(err < 0) return err;
        }

        if(env.enable_keytime){
            struct kt_ctrl kt_ctrl = {true,env.enable_cpu,env.enable_myproc,env.pid,env.tgid};
            err = update_kt_ctrl_map(kt_ctrl);
            if(err < 0) return err;
        }

        if(env.enable_lock){
            struct lock_ctrl lock_ctrl = {true,env.enable_myproc,env.pid,env.tgid};
            err = update_lock_ctrl_map(lock_ctrl);
            if(err < 0) return err;
        }

        if(env.enable_syscall){
            struct sc_ctrl sc_ctrl = {true,env.enable_myproc,env.pid,env.tgid,env.syscalls};
            err = update_sc_ctrl_map(sc_ctrl);
            if(err < 0) return err;
        }

        if(env.enable_schedule){
            struct sched_ctrl sched_ctrl = {true,env.pid,env.cpu_id,env.tgid};
            err = update_sched_ctrl_map(sched_ctrl);
            if(err < 0) return err;
        }

        if(env.time!=0) pause();
    }else if(env.usemode == 2){             // deactivate mode
        err = deactivate_mode();
        if(err<0){
            fprintf(stderr, "Failed to deactivate\n");
            return err;
        }
    }else if(env.usemode == 3){             // finish mode
        const char *command = "pkill proc_image";
        int status = system(command);
        if (status == -1) {
            perror("system");
        }
    }else{
        // 输出help信息
        printf("Please enter the usage mode(activate/deactivate/finish) before selecting the function\n");
        argp_help(&argp, stderr, ARGP_HELP_LONG, argv[0]);
    }

    return 0;
}