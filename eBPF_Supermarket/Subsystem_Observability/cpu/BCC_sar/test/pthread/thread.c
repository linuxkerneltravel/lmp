#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

void *thread_funtion(void *arg);

char msg[] = "Hello World!";

int main() {
    int res;
    pthread_t a_thread;
    void *thread_result;

    res = pthread_create(&a_thread, NULL, thread_funtion, msg);
    if (res != 0) {
        perror("Thread creation failed.");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for a thread to finish...\n");
    res = pthread_join(a_thread, &thread_result);

    if (res != 0) {
        perror("Thread join error!");
        exit(EXIT_FAILURE);
    }

    printf("Thread joined, it returned %s\n", (char *)thread_result);
    printf("Message is now %s\n", msg);
    exit(EXIT_SUCCESS);
}

void *thread_funtion(void *arg) {
    printf("thread_function is running, Argument is %s\n", (char *)arg);
    sleep(3);
    strcpy(msg, "bye!");
    pthread_exit("Thank you for my execution!");
}