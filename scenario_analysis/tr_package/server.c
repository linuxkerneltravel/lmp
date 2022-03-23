#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>

#define MAXLINE 4096
int main(int argc,char **argv)
{
	int listenfd,connfd;
	struct sockaddr_in servaddr;
	char buff[4096];
	int n;

	if((listenfd = socket(AF_INET,SOCK_STREAM,0)) == -1){
		printf("create socket err:%s %d",strerror(errno),errno);
		exit(0);
	}
	memset(&servaddr,0,sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(5555);
    if( bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
    	printf("绑定套接字错误: %s(错误号: %d)\n",strerror(errno),errno);
    	exit(0);
    }
    if( listen(listenfd, 10) == -1){
  		printf("监听套接字错误: %s(错误号: %d)\n",strerror(errno),errno);
    	exit(0);
    }
    printf("======等待客户端的请求======\n");
    while(1){
	    if( (connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
    	    printf("接收请求错误: %s(错误号: %d)",strerror(errno),errno);
        	continue;
    	}
    	n = recv(connfd, buff, MAXLINE, 0);
    	buff[n] = '\0';
	    printf("从客户端收到消息: %s", buff);
    	close(connfd);
    }
    close(listenfd);
}
