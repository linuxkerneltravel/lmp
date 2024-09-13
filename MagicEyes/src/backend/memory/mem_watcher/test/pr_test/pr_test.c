#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define ALLOC_SIZE 1024*1024*1024 // 分配 512 MB 内存

int main() {
    void *memory;
    printf("Allocating memory...\n");
    memory = malloc(ALLOC_SIZE);
    if (!memory) {
        perror("Failed to allocate memory");
        return -1;
    }

    // 填充内存以确保页面被分配
    printf("Filling memory...\n");
    for (size_t i = 0; i < ALLOC_SIZE; ++i) {
        ((char*)memory)[i] = (char)i;
    }

    printf("Freeing memory...\n");
    free(memory);

    // 给内核更多时间处理回收
    printf("Sleeping for 10 seconds...\n");
    sleep(10);  // 增加等待时间到 10 秒

    printf("Memory management demo finished.\n");
    return 0;
}

// 分配大量内存。
//填充内存以确保页面分配。
//释放内存。
//等待一段时间以允许内核处理任何可能的内存回收。