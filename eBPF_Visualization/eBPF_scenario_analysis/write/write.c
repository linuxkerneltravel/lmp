#define _GNU_SOURCE
#include<stdio.h>
 
#include <unistd.h>
 
#include<string.h>
#include <fcntl.h>
int main(void){
 
   int fd=open("./nunjui.txt",O_WRONLY  | O_CREAT);
 
lseek(fd, 5, SEEK_SET);
   char buf[1024]={"0123456789"};
   pid_t pid = getpid();
   printf("当前进程ID：%d\n", pid);
 
   getchar();
   int len=write(fd,buf,strlen(buf));

 
   close(fd);
 
   return 0;
 
}
