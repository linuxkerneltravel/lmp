#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

// 线程函数
void *thread_function(void *arg) {
    while (1) {
        // 打印当前线程的pid
        printf("Thread PID: %d\n", getpid());
        // 等待一秒
        sleep(1);
    }
    pthread_exit(NULL);
}

// 创建线程的函数
void create_thread() {
    pthread_t thread;
    int rc;

    // 创建线程
    rc = pthread_create(&thread, NULL, thread_function, NULL);
    if (rc) {
        fprintf(stderr, "Error: pthread_create() failed with code %d\n", rc);
        exit(EXIT_FAILURE);
    }
}

int main() {
    // 打印主进程的pid
    printf("Main process PID: %d\n", getpid());

    // 调用函数创建线程
    create_thread();

    // 主进程死循环打印pid
    while (1) {
        printf("Main process PID: %d\n", getpid());
        // 等待一秒
        sleep(1);
    }

    return 0;
}