#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <stdint.h>
#include <string.h>

// Futex 原子变量
volatile int futex_var = 0;

// Futex 系统调用的封装函数
int futex_wait(volatile int *uaddr, int val) {
    return syscall(SYS_futex, uaddr, FUTEX_WAIT, val, NULL, NULL, 0);
}

int futex_wake(volatile int *uaddr, int num_wake) {
    return syscall(SYS_futex, uaddr, FUTEX_WAKE, num_wake, NULL, NULL, 0);
}

// 等待线程函数
void* wait_thread(void* arg) {
    int thread_id = *(int*)arg;
    printf("Thread %d: Waiting on futex...\n", thread_id);
    
    // 等待 futex_var 为 0
    int ret = futex_wait(&futex_var, 0);
    if (ret == -1) {
        perror("futex_wait");
    }
    
    printf("Thread %d: Futex was awakened!\n", thread_id);
    
    return NULL;
}

// 唤醒线程函数
void* wake_thread(void* arg) {
    for (int i = 0; i < 10; i++) {
        // 模拟一些工作延迟
        sleep(1);
        
        printf("Wake thread: Waking up thread %d...\n", i + 1);
        
        // 唤醒一个等待的线程
        futex_var = 1;  // 修改 futex_var，允许一个线程继续
        int ret = futex_wake(&futex_var, 1);  // 唤醒一个等待的线程
        if (ret == -1) {
            perror("futex_wake");
        } else {
            printf("Wake thread: Thread %d wake successful!\n", i + 1);
        }
        
        // 重置 futex_var 为 0，确保下一个线程继续等待
        futex_var = 0;
    }
    
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
    int tgid = -1;
    
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
    pthread_t wait_threads[10];
    pthread_t wake_thread_id;
    pid_t tgid = get_tgid();
    printf("TGID:%d\n", tgid);
    printf("lock_addr :0x%-8x\n",&futex_var);
    int tmp;
    scanf("%d",&tmp);
    // 创建等待线程的 ID 数组
    int thread_ids[10];
    for (int i = 0; i < 10; i++) {
        thread_ids[i] = i + 1;
    }

    // 创建 10 个等待线程
    for (int i = 0; i < 10; i++) {
        pthread_create(&wait_threads[i], NULL, wait_thread, &thread_ids[i]);
    }

    // 创建唤醒线程
    pthread_create(&wake_thread_id, NULL, wake_thread, NULL);

    // 等待所有等待线程结束
    for (int i = 0; i < 10; i++) {
        pthread_join(wait_threads[i], NULL);
    }

    // 等待唤醒线程结束
    pthread_join(wake_thread_id, NULL);
    
    printf("Futex test completed.\n");
    return 0;
}
