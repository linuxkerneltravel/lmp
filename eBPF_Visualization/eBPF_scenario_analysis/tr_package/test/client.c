#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/in.h>
#include <memory.h>
#define PORT 5555
int main() {
    int sock_service;
    struct sockaddr_in addr_service;
	char ch = getchar();
    sock_service = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_service == -1) {
        perror("socked error\n");
        return 0;
    }

    addr_service.sin_family = AF_INET;
    addr_service.sin_port = htons(PORT);
    addr_service.sin_addr.s_addr = htonl(INADDR_ANY);
    bzero(&(addr_service.sin_zero), 8);
	inet_pton(AF_INET, "127.0.0.1", &addr_service.sin_addr);
    connect(sock_service, (struct sockaddr*) &addr_service, sizeof(struct sockaddr));
    char buffer[1024];
    int size=0;
    while(1){
     size=read(0,buffer,1024);//从终端读入数据
     if(size>0){
         write(sock_service,buffer,size);//发送数据
        // size=read(sock_service,buffer,1024); //从服务器得到数据
        // write(1,buffer,size);//在终端显示读到的数据
     }
    }
    close(sock_service);
}
