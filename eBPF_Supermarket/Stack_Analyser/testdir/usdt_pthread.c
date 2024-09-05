#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

// 线程函数
void *thread_function(void *arg)
{
    while (1)
    {
        // 打印当前线程的pid
        printf("Thread ID: %d\n", gettid());
        // 等待一秒
        sleep(1);
    }
};

int main()
{

    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_function, NULL))
    {
        fprintf(stderr, "Error: pthread_create() failed\n");
        exit(EXIT_FAILURE);
    }

    thread_function(NULL);

    return 0;
};