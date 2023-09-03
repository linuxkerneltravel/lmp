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
#include <sys/wait.h>
#include <sys/syscall.h>

#define gettid() syscall(__NR_gettid)

void *func(void *arg)
{
   int tpid;

   tpid = gettid();
   printf("新线程pid:%d,睡眠3s后退出\n",tpid);
   sleep(3);
   printf("新线程退出\n");
}

int main() {
   int pid,stop;
   int err;
   pthread_t tid;

   pid = getpid();
   printf("test进程的PID:%d\n", pid);
   printf("输入任意数字继续程序的运行:");
   //scanf("%d",&stop);                   // 使用时将其取消注释
   printf("程序开始执行...\n");
   printf("\n");

   // 逻辑1：加入sleep逻辑使进程睡眠3秒，即offCPU 3秒
   printf("逻辑1:\n");
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

   // 逻辑2：加入互斥锁逻辑，为了应对复杂场景，模拟进程异常地递归加锁解锁
   printf("逻辑2:\n");
   pthread_mutex_t mutex1;
   pthread_mutex_t mutex2;
   pthread_mutex_init(&mutex1, NULL);
   pthread_mutex_init(&mutex2, NULL);
   printf("mutex1_ptr:%llu\n",(long long unsigned int)&mutex1);
   printf("mutex2_ptr:%llu\n",(long long unsigned int)&mutex2);
   pthread_mutex_lock(&mutex1);
   printf("进程成功持有锁mutex1\n");
   sleep(3);
   pthread_mutex_lock(&mutex2);
   printf("进程成功持有锁mutex2\n");
   pthread_mutex_unlock(&mutex1);
   printf("进程成功解锁mutex1\n");
   sleep(3);
   pthread_mutex_unlock(&mutex2);
   printf("进程成功解锁mutex2\n");
   pthread_mutex_destroy(&mutex1);
   pthread_mutex_destroy(&mutex2);
   printf("\n");

   // 逻辑3：加入fork和vfork逻辑，创建子进程让子进程睡眠3秒，以表示它存在的时间
   printf("逻辑3:\n");
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

   // 逻辑4：加入pthread_create逻辑，创建线程让线程睡眠3秒，以表示它存在的时间
   printf("逻辑4:\n");
   err = pthread_create(&tid,NULL,&func,NULL);
   if(err != 0) printf("线程创建失败\n");
   sleep(6);      // 等待新线程执行完毕
   printf("\n");

   // 逻辑5：加入读写锁逻辑，在读模式或写模式下上锁后睡眠3s，以表示持有锁时间
   printf("逻辑5:\n");
   pthread_rwlock_t rwlock;
   pthread_rwlock_init(&rwlock,NULL);
   printf("rwlock_ptr:%llu\n",(long long unsigned int)&rwlock);
   pthread_rwlock_rdlock(&rwlock);
   printf("进程在读模式下锁定读写锁rwlock\n");
   sleep(3);
   pthread_rwlock_unlock(&rwlock);
   printf("进程成功解锁rwlock\n");
   pthread_rwlock_wrlock(&rwlock);
   printf("进程在写模式下锁定读写锁rwlock\n");
   sleep(3);
   pthread_rwlock_unlock(&rwlock);
   printf("进程成功解锁rwlock\n");
   pthread_rwlock_destroy(&rwlock);
   printf("\n");

   return 0;
}
