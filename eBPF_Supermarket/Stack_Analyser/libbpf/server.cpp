// server_multithread.cpp
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <fcntl.h>
#include "include/sa_user.h"

// 处理客户端连接的函数
void clientHandler(int clientSocket) {
    diy_header AHeader;
    int bytes;
    char filename[32];
    char *data = NULL;
    while (true) {
        // 接收客户端数据
        bytes = recv(clientSocket, &AHeader, sizeof(AHeader), 0);
        if (bytes <= 0) {
            std::cerr << "Client " << clientSocket << " closed or err" << std::endl;
            break;
        }
        if(AHeader.magic) {
            continue;
        }
        std::string filename = AHeader.name;
        filename += std::to_string(clientSocket);
        auto fd = open(filename.c_str(),  O_CREAT | O_APPEND | O_WRONLY, 0666);
        printf("Recv %ld Byte from Client %d\n", AHeader.len, clientSocket);
        char *data = (char *)malloc(AHeader.len);
        if(!data) {
            std::cout << "Allocate err" << std::endl;
            break;
        }
        bytes = recv(clientSocket, data, AHeader.len, 0);
        if (bytes <= 0) {
            std::cerr << "Client " << clientSocket << " closed or err" << std::endl;
            break;
        }
        bytes = write(fd, data, AHeader.len);
        free(data);
        if(bytes <= 0) {
            std::cerr << "Client " << clientSocket << " Write err" << std::endl;
            continue;
        }
        std::cout << "Saved in " << filename << std::endl;
        close(fd);
        // std::cout << "接收到的数据: " << data << std::endl;
    }

    printf("Client %d exiting\n", clientSocket);
    close(clientSocket);
}

int main(int argc, char const *argv[]) {
    // 创建 socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    // 服务器地址信息
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    int PortAddr = 12345;
    if(argc > 1) {
        PortAddr = atoi(argv[1]);
    }
    serverAddress.sin_port = htons(PortAddr);

    // 绑定端口
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Error binding socket" << std::endl;
        close(serverSocket);
        return -1;
    }

    // 监听连接
    if (listen(serverSocket, 5) == -1) {
        std::cerr << "Error listening for connections" << std::endl;
        close(serverSocket);
        return -1;
    }

    std::cout << "Waiting for connection..." << std::endl;

    std::vector<std::thread> clientThreads;

    while (true) {
        // 接受连接
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == -1) {
            std::cerr << "Error accepting connection" << std::endl;
            close(serverSocket);
            return -1;
        }

        std::cout << "Client " << clientSocket << " connected successfully" << std::endl;

        // 创建新线程处理客户端连接
        std::thread clientThread(clientHandler, clientSocket);
        clientThread.detach(); // 分离线程，允许线程独立运行

        clientThreads.push_back(std::move(clientThread));
    }

    // 关闭服务器套接字
    close(serverSocket);

    return 0;
}
