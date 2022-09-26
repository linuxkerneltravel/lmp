#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#define NUM_THREADS 6

// 传入的参数是线程的编号
void *thread_function(void *arg);

int main() {
    int res;
    pthread_t athread[NUM_THREADS];
    void *thread_result;
    int i;

    for (i = 0; i < NUM_THREADS; i++) {
        res = pthread_create(&athread[i], NULL, thread_function, (void *)i);
        if (res != 0) {
            perror("Create thread err");
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }
    printf("Wait for pthreads to finish.\n");

    for (i = 0; i < NUM_THREADS; i++) {
        res = pthread_join(athread[i], &thread_result);
        if (res == 0) {
            printf("pick up thread %d.\n", i);
        }
        else {
            perror("thread join %d failed.");
        }
    }
    printf("All done.\n");
    exit(EXIT_SUCCESS);
}

void *thread_function(void *arg) {
    int num = (int)arg;
    int randn;

    printf("[%d]thread is running, arg is %d.\n", getpid(), num);
    randn = 1 + (int)(9.0*rand()/(RAND_MAX+1.0));
    sleep(randn); // sleep 1~10s

    printf("Bye from %d, sleep %d\n", num, randn);
    pthread_exit(NULL);
}