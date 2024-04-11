#include "stdio.h"
static int hello(int a,int b){
    return a+b;
}
int main(int argc,char *argv[])
{
    int a=1,b=2,c;
    c=hello(a,b);
    printf("first %d second %d result %d\n",a,b,c);
    return(0);
}