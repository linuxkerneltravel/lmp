#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFFER_SIZE 1024

int main() {
    // 打印当前进程号
    printf("Process ID: %d\n", getpid());

    // 申请内存
    char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // 文件描述符
    int fd = open("data.txt", O_CREAT | O_WRONLY, 0644);
    if (fd == -1) {
        fprintf(stderr, "Failed to open file\n");
        free(buffer);
        return 1;
    }

    // 写数据
    printf("Writing data. Process ID: %d\n", getpid());
    write(fd, "Hello, World!\n", 14);

    // 关闭文件描述符
    close(fd);

    // 打开文件以读取数据
    fd = open("data.txt", O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Failed to open file for reading\n");
        free(buffer);
        return 1;
    }

    // 读取数据
    printf("Reading data. Process ID: %d\n", getpid());
    ssize_t bytesRead = read(fd, buffer, BUFFER_SIZE);
    if (bytesRead == -1) {
        fprintf(stderr, "Failed to read data from file\n");
        free(buffer);
        close(fd);
        return 1;
    }

    // 输出读取的数据
    printf("Data read: %s\n", buffer);

    // 关闭文件描述符
    close(fd);

    // 持续打印进程号
    while(1) {
        printf("Still running. Process ID: %d\n", getpid());
        sleep(1); // 暂停一秒钟
    }

    // 释放内存
    free(buffer);
    printf("Memory freed. Process ID: %d\n", getpid());

    return 0;
}
