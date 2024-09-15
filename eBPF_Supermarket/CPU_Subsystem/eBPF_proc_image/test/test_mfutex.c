#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// 定义一个互斥锁
pthread_mutex_t mutex;

// 线程的执行函数
void *thread_func(void *arg) {
    int thread_id = *(int *)arg;
    
    printf("Thread %d: Trying to acquire the mutex\n", thread_id);
    
    // 尝试获取互斥锁
    pthread_mutex_lock(&mutex);
    printf("Thread %d: Mutex acquired\n", thread_id);
    
    // 模拟线程持有互斥锁的操作
    sleep(3);
    
    // 释放互斥锁
    printf("Thread %d: Releasing the mutex\n", thread_id);
    pthread_mutex_unlock(&mutex);
    
    return NULL;
}
pid_t get_tgid() {
    pid_t pid = getpid();
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("打开 proc/pid/status 文件失败");
        return -1;
    }
    
    char line[256];
    int tgid = -1,cpuid = -1;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Tgid:", 5) == 0) {
            sscanf(line, "Tgid: %d", &tgid);
            break;
        }
    }
    
    fclose(fp);
    return tgid;
}
int main() {
    pthread_t threads[10];
    int thread_ids[10];
    int i;
    pid_t tgid = get_tgid();
    printf("TGID:%d\n",tgid);
    int tmp;
    scanf("%d",&tmp);
    // 初始化互斥锁
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        fprintf(stderr, "Failed to initialize mutex\n");
        return EXIT_FAILURE;
    }
    
    // 创建5个线程
    for (i = 0; i < 10; i++) {
        thread_ids[i] = i + 1;
        if (pthread_create(&threads[i], NULL, thread_func, &thread_ids[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i + 1);
            return EXIT_FAILURE;
        }
    }
    
    // 等待所有线程结束
    for (i = 0; i < 10; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "Failed to join thread %d\n", i + 1);
            return EXIT_FAILURE;
        }
    }
    
    // 销毁互斥锁
    pthread_mutex_destroy(&mutex);
    
    return EXIT_SUCCESS;
}
