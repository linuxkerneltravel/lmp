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
// process image of the user test program

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <argp.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/fcntl.h>
#include <string.h>

#define gettid() syscall(__NR_gettid)

static struct env {
   bool keytime_test;
   bool lock_test;
   bool resource_test;
   bool syscall_test;
   bool schedule_test;
} env = {
   .keytime_test = false,
   .lock_test = false,
   .resource_test = false,
   .syscall_test = false,
   .schedule_test = false,
};

const char argp_program_doc[] ="To test process_image.\n";

static const struct argp_option opts[] = {
   { "keytime", 'k', NULL, 0, "To test keytime_image" },
   { "lock", 'l', NULL, 0, "To test lock_image" },
   { "resource", 'r', NULL, 0, "To test resource_image" },
   { "syscall", 's', NULL, 0, "To test syscall_image" },
   { "schedule", 'S', NULL, 0, "To test schedule_image" },
   { "all", 'a', NULL, 0, "To test all_image" },
   { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help" },
   {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'a':
				env.keytime_test = true;
				env.lock_test = true;
				env.resource_test = true;
				env.syscall_test = true;
            env.schedule_test = true;
				break;
		case 'k':
				env.keytime_test = true;
				break;
		case 'l':
            env.lock_test = true;
            break;
      case 'r':
            env.resource_test = true;
            break;
		case 's':
				env.syscall_test = true;
            break;
      case 'S':
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
   printf("test_proc进程的PID:%d\n", pid);
   printf("输入任意数字继续程序的运行:");
//   scanf("%d",&stop);                   // 使用时将其取消注释
   printf("程序开始执行...\n");
   printf("\n");

   if(env.keytime_test){
      printf("KEYTIME_TEST-----------------------------------------------\n");

      // fork、vfork逻辑: 创建子进程让子进程睡眠3秒，以表示它存在的时间
      printf("fork、vfork逻辑:\n");
      //fork
      pid = fork();
      if(pid < 0){
         printf("fork error\n");
      }else if(pid == 0){
         pid = getpid();
         printf("(fork)子进程pid:%d,睡眠3s后退出\n",pid);
         sleep(3);
         exit(0);
      }else{
         pid = wait(NULL);
         printf("(fork)pid为%d的子进程退出\n",pid);
      }
      //vfork
      pid = vfork();
      if(pid < 0){
         printf("fork error\n");
      }else if(pid == 0){
         pid = getpid();
         printf("(vfork)子进程pid:%d,睡眠3s后退出\n",pid);
         sleep(3);
         exit(0);
      }else{
         pid = wait(NULL);
         printf("(vfork)pid为%d的子进程退出\n",pid);
      }
      printf("\n");

      // pthread_create逻辑: 创建线程并让线程睡眠3秒，以表示它存在的时间
      printf("pthread_create逻辑:\n");
      err = pthread_create(&tid,NULL,&func,NULL);
      if(err != 0) printf("线程创建失败\n");
      sleep(6);      // 等待新线程执行完毕
      printf("\n");

      // 进程上下CPU逻辑: 利用sleep函数使进程睡眠3秒,即 offCPU 3秒
      printf("进程上下CPU逻辑:\n");
      time_t now = time(NULL);
      struct tm *localTime = localtime(&now);
      printf("sleep开始时间:%04d-%02d-%02d %02d:%02d:%02d\n",
            localTime->tm_year + 1900, localTime->tm_mon + 1, localTime->tm_mday,
            localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
      sleep(3);
      time_t afterSleep = time(NULL);
      struct tm *localTimeAfterSleep = localtime(&afterSleep);
      printf("sleep结束时间:%04d-%02d-%02d %02d:%02d:%02d\n",
            localTimeAfterSleep->tm_year + 1900, localTimeAfterSleep->tm_mon + 1, localTimeAfterSleep->tm_mday,
            localTimeAfterSleep->tm_hour, localTimeAfterSleep->tm_min, localTimeAfterSleep->tm_sec);
      printf("程序睡眠3s!\n");
      printf("\n");

      // execve逻辑: 替换当前进程，ARGV和ENVP以NULL指针结束
      // 若出错，返回-1；若成功，不返回
      char *argvv[] = { "ls", "-l", NULL };
      char *envp[] = { "PATH=/bin", NULL };
      printf("execve逻辑:\n");
      execve("/bin/ls", argvv, envp);
      perror("execve");
      printf("\n");

      // exit逻辑: 可自行输入退出值
      printf("exit逻辑: \n");
      int error_code;
      printf("请输入程序退出的error_code值:");
      scanf("%d",&error_code);
      exit(error_code);

   }

   if(env.lock_test){
      printf("LOCK_TEST--------------------------------------------------\n");

      // 用户态自旋锁逻辑
      printf("用户态自旋锁逻辑:\n");
      pthread_spinlock_t spinlock;
      // 经实验发现，pthread_spin_init() 函数内部会调用 pthread_spin_unlock() 函数
      pthread_spin_init(&spinlock,PTHREAD_PROCESS_PRIVATE);
      printf("spinlock_ptr:%llu\n",(long long unsigned int)&spinlock);
      pthread_spin_lock(&spinlock);
      printf("进程成功持有用户态自旋锁spinlock\n");
      sleep(3);
      pthread_spin_unlock(&spinlock);
      printf("进程成功解锁spinlock\n");
      pthread_spin_trylock(&spinlock);
      printf("进程成功尝试持有用户态自旋锁spinlock\n");
      sleep(3);
      pthread_spin_unlock(&spinlock);
      printf("进程成功解锁spinlock\n");
      printf("\n");
      
      // 用户态互斥锁逻辑: 为了应对复杂场景，模拟进程异常地递归加锁解锁
      printf("用户态互斥锁逻辑:\n");
      pthread_mutex_t mutex1;
      pthread_mutex_t mutex2;
      pthread_mutex_init(&mutex1, NULL);
      pthread_mutex_init(&mutex2, NULL);
      printf("mutex1_ptr:%llu\n",(long long unsigned int)&mutex1);
      printf("mutex2_ptr:%llu\n",(long long unsigned int)&mutex2);
      pthread_mutex_lock(&mutex1);
      printf("进程成功持有用户态互斥锁mutex1\n");
      sleep(3);
      pthread_mutex_lock(&mutex2);
      printf("进程成功持有用户态互斥锁mutex2\n");
      pthread_mutex_unlock(&mutex1);
      printf("进程成功解锁mutex1\n");
      sleep(3);
      pthread_mutex_unlock(&mutex2);
      printf("进程成功解锁mutex2\n");
      pthread_mutex_destroy(&mutex1);
      pthread_mutex_destroy(&mutex2);
      printf("\n");

      // 用户态读写锁逻辑: 在读模式或写模式下上锁后睡眠3s，以表示持有锁时间
      printf("用户态读写锁逻辑:\n");
      pthread_rwlock_t rwlock;
      pthread_rwlock_init(&rwlock,NULL);
      printf("rwlock_ptr:%llu\n",(long long unsigned int)&rwlock);
      pthread_rwlock_rdlock(&rwlock);
      printf("进程在读模式下锁定用户态读写锁rwlock\n");
      sleep(3);
      pthread_rwlock_unlock(&rwlock);
      printf("进程成功解锁rwlock\n");
      pthread_rwlock_wrlock(&rwlock);
      printf("进程在写模式下锁定用户态读写锁rwlock\n");
      sleep(3);
      pthread_rwlock_unlock(&rwlock);
      printf("进程成功解锁rwlock\n");
      pthread_rwlock_destroy(&rwlock);
      printf("\n");
   }

   if(env.resource_test){
      printf("RESOURSE_TEST----------------------------------------------\n");
      
      clock_t start_time;
      printf("CPU 密集型任务的模拟：\n");
      time_t now = time(NULL);
      struct tm *localTime = localtime(&now);
      printf("%02d:%02d:%02d  空循环5秒钟\n",
            localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
      start_time = clock();
      while ((clock() - start_time) < 5 * CLOCKS_PER_SEC) {}
      now = time(NULL);
      localTime = localtime(&now);
      printf("%02d:%02d:%02d  空循环结束\n\n",
            localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
      
      printf("内存密集型任务的模拟：\n");
      printf("分配给进程3GB的内存,并赋初值\n");
      long long int total_memory = 3LL * 1024 * 1024 * 1024;
      char *memory = (char *)malloc(total_memory);
      if (memory == NULL) {
         printf("内存分配失败！\n");
         return 1;
      }
      memset(memory, 'A', total_memory);
      printf("空循环5秒钟以代表占有时间\n\n");
      start_time = clock();
      while ((clock() - start_time) < 5 * CLOCKS_PER_SEC) {}

      printf("IO 密集型任务的模拟：\n");
      const char *command = "rm io_test.txt";
      printf("每秒向文件读和写2MB,持续5s\n");
      for(int i = 0; i < 5; i++){
         FILE *file = fopen("./io_test.txt", "w");
         if (file == NULL) {
            break;
         }
         fwrite(memory, 1, 2*1024*1024, file);
         fclose(file);
         file = fopen("./io_test.txt", "r");
         if (file == NULL) {
            break;
         }
         fread(memory, 1, 2*1024*1024, file);
         fclose(file);
         sleep(1);
      }
      free(memory);
      system(command);
      
      printf("\n");
   }

   if(env.syscall_test){
      printf("SYSCALL_TEST----------------------------------------------\n");

      // 系统调用序列逻辑(参考 UnixBench 中的 syscall 测试)
      printf("系统调用序列逻辑:\n");
      printf("每调用一次 SYS_getpid 系统调用睡眠 1 s,循环 10 次\n");
      int count = 10;
      while(count){
         syscall(SYS_getpid);
         count--;
         sleep(1);
      }
   }

   if(env.schedule_test){
      printf("SCHEDULE_TEST----------------------------------------------\n");

      // 调度延迟测试逻辑：创建线程执行 sysbench --threads=32 --time=10 cpu run，观察加压前后的变化
      char *argvv[] = { "/usr/bin/sysbench", "--threads=32", "--time=10", "cpu", "run", NULL };
      char *envp[] = { "PATH=/bin", NULL };
      printf("调度延迟测试逻辑：\n");
      printf("执行指令 sysbench --threads=32 --time=10 cpu run\n");
      execve("/usr/bin/sysbench", argvv, envp);
      perror("execve");
      
      printf("\n");
   }

   return 0;
}
