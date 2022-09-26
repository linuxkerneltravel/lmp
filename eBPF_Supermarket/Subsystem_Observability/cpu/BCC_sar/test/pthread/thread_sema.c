#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

void *thread_function(void *arg);
sem_t bin_sem;

#define WORK_SIZE 1024
char work_area[WORK_SIZE];

int main() {
    int res;
    pthread_t a_thread;
    void *thread_result;

    res = sem_init(&bin_sem, 0, 0);
    if (res != 0) {
        perror("Semaphore Create Error!");
        exit(EXIT_FAILURE);
    }

    res = pthread_create(a_thread, NULL, thread_function, NULL);
    if (res != 0) {
        perror("create p err");
        exit(EXIT_FAILURE);
    }

    printf("Input text, 'end' to finish:\n");
    while(strncmp("end", work_area, 3) != 0) {
        fgets(work_area, WORK_SIZE, stdin);
        sem_post(&bin_sem); // 提供信息&唤醒
    }

    printf("wait for p to finish\n");
    res = pthread_join(a_thread, &thread_result);
    if (res != 0) {
        perror("join err");
        exit(EXIT_FAILURE);
    }

    printf("pthread joined.\n");
    sem_destroy(&bin_sem);
    exit(EXIT_SUCCESS);
}

void *thread_function(void *arg) {
    sem_wait(&bin_sem);
    while(strncmp(work_area, "end", 3) != 0) {
        printf("You input %d chars.\n", strlen(work_area) - 1);
        sem_wait(&bin_sem);
    }
    pthread_exit(NULL);
}