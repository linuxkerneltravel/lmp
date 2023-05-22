#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT    23456
#define BUFSIZE 1024

int main(void)
{
    int listenfd, connfd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    char buf[BUFSIZE];
    ssize_t n;

    // 创建监听套接字
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1) {
        perror("socket error");
        exit(1);
    }

    // 绑定服务器端地址
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        perror("bind error");
        exit(1);
    }

    // 将监听套接字转换为监听状态
    if (listen(listenfd, SOMAXCONN) == -1) {
        perror("listen error");
        exit(1);
    }

    printf("Server is listening on port %d...\n", PORT);

    while (1) {
        //模拟服务器繁忙，不accept请求
    }

    close(listenfd);
    return 0;
}