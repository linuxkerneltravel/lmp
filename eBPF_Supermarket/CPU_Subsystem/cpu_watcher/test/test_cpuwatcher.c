// Copyright 2024 The LMP Authors.
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
// author: albert_xuu@163.com zhangxy1016304@163.com zhangziheng0525@163.com
//
// process image of the user test program

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <argp.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/fcntl.h>
#include <string.h>

#define gettid() syscall(__NR_gettid)

static struct env {
   bool sar_test;
   bool cs_delay_test;
   bool sc_delay_test;
   bool mq_delay_test;
   bool preempt_test;
   bool schedule_test;
} env = {
   .sar_test = false,
   .cs_delay_test = false,
   .sc_delay_test = false,
   .mq_delay_test = false,
   .preempt_test = false,
   .schedule_test = false,
};

const char argp_program_doc[] ="To test cpu_watcher.\n";

static const struct argp_option opts[] = {
   { "sar", 's', NULL, 0, "To test sar" },
   { "cs_delay", 'c', NULL, 0, "To test cs_delay" },
   { "sc_delay", 'S', NULL, 0, "To test sc_delay" },
   { "mq_delay", 'm', NULL, 0, "To test mq_delay" },
   { "preempt_delay", 'p', NULL, 0, "To test preempt_delay" },
   { "schedule_delay", 'd', NULL, 0, "To test schedule_delay"},
   { "all", 'a', NULL, 0, "To test all" },
   { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
   {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'a':
				env.sar_test = true;
				env.cs_delay_test = true;
				env.mq_delay_test = true;
				env.preempt_test = true;
                env.sc_delay_test = true;
                env.schedule_test = true;
				break;
		case 's':
				env.sar_test = true;
				break;
		case 'c':
            env.cs_delay_test = true;
            break;
        case 'S':
            env.sc_delay_test = true;
            break;
		case 'm':
				env.mq_delay_test = true;
            break;
        case 'p':
            env.preempt_test = true;
            break;
        case 'd':
            env.schedule_test = true;
            break;
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
      default:
         return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

void *func(void *arg)
{
   int tpid;

   tpid = gettid();
   printf("新线程pid:%d,睡眠3s后退出\n",tpid);
   sleep(3);
   printf("新线程退出\n");
}

int main(int argc, char **argv){
    int pid,stop;
    int err;
    pthread_t tid;
    static const struct argp argp = {
    	.options = opts,
    	.parser = parse_arg,
    	.doc = argp_program_doc,
    };

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
    	return err;

    pid = getpid();
    printf("test_proc进程的PID:【%d】\n", pid);
    printf("输入任意数字继续程序的运行:");
    scanf("%d",&stop);                   // 使用时将其取消注释
    printf("程序开始执行...\n");
    printf("\n");

    if(env.sar_test){
    /*sar的测试代码*/
    }

    if(env.cs_delay_test){
    /*cs_delay的测试代码*/
    }

    if(env.sc_delay_test){
    /*sc_delay的测试代码*/
    }

    if(env.mq_delay_test){
    /*mq_delay的测试代码*/
        system("./sender & ./receiver");
        sleep(60);
        system("^Z");
    }

    if(env.preempt_test){
    /*preempt_delay的测试代码*/
    }

    if(env.schedule_test){
    /*schedule_delay的测试代码*/
    }

    return 0;
}
