#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define ALLOC_SIZE_SMALL 512*1024*1024   // 分配 512 MB 内存
#define ALLOC_SIZE_LARGE 1024*1024*1024  // 分配 1 GB 内存

void allocate_memory(size_t size) {
    void *memory;

    printf("Allocating %lu MB memory...\n", size / (1024*1024));
    memory = malloc(size);
    if (!memory) {
        perror("Failed to allocate memory");
        return;
    }

    // 填充内存以确保页面被分配
    printf("Filling memory...\n");
    for (size_t i = 0; i < size; ++i) {
        ((char*)memory)[i] = (char)i;
    }

    printf("Freeing memory...\n");
    free(memory);

    // 给内核更多时间处理回收
    printf("Sleeping for 10 seconds...\n");
    sleep(10);  // 增加等待时间到 10 秒

    printf("Memory management operation finished.\n");
}

int main() {
    printf("Starting memory management demo...\n");

    // 分配和释放多次小块内存
    for (int i = 0; i < 5; ++i) {
        allocate_memory(ALLOC_SIZE_SMALL);
    }

    // 分配和释放多次大块内存
    for (int i = 0; i < 5; ++i) {
        allocate_memory(ALLOC_SIZE_LARGE);
    }

    printf("Memory management demo finished.\n");
    return 0;
}
