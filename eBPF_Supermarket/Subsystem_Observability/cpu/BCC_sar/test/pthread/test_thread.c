#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

#define MAX_THREAD 4

void *thread_func(void *arg) {
    while(1) {

    }
}

int main() {
    pthread_t thread[MAX_THREAD];
    int res;
    for (int i = 0; i < MAX_THREAD; i++) {
        res = pthread_create(&thread[i], NULL, thread_func, NULL);
        assert(res == 0);
    }

    while(1);
}