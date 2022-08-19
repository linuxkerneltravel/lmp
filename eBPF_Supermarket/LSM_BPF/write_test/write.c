#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char buffer[50] = "hello==>qingyang2199\n";   //buffer里面写上String类型的内容
    int count;
    int fd = open ("abc.txt",O_RDWR);
    if (fd == -1)
    {
        fprintf(stderr,"can't open file:[%s]\n","abc.txt");  //打不开文件
        exit(EXIT_FAILURE);
    }
   
   for(int i=0; i<5000000000000000; ++i){
   
    count = write(fd,buffer,strlen(buffer));  //在这里【write函数】将buffer里的内容，写入文件abc.txt
    if (count == -1)
    {
        fprintf(stderr,"write error\n");  //写的时候出错
        exit(EXIT_FAILURE);
    }
   }
    exit(EXIT_SUCCESS);
}
