#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <time.h>

/**            
* main：1. 创建5个线程，每个线程在2-10s内随机结束
        2. 创建5个子进程，每个子进程再分别创建一个孙子进程，总共10个进程，每个进程在2-10s内
        随机结束
*/

void *func(void *num)
{
    int t = *(int *)num;
    printf("thread : pid is %8ld, tgid is %10d, ppid is %12d die after %d s\n", syscall(SYS_gettid), getpid(), getppid(), t);
    sleep(t);
    printf("thread exiting..\n");
}

void alarm_handler()
{
    printf("this is %10ld ... goodbye\n", syscall(SYS_gettid));
}

int randomNum()
{
    srand((unsigned)time(NULL));
    return rand() % 8 + 2;
}
int main(int argc, char *argv[])
{
    prctl(PR_SET_NAME, "main");
    int num = 0, status = 0;
    pthread_t pn[5];
    pid_t pid = getpid();

    printf("main tgid: %d , pid = %ld\n", pid, syscall(SYS_gettid));
    signal(SIGALRM, alarm_handler);

    // 主线程创建5个线程
    for (int i = 0; i < 5; i++)
    {

        num = randomNum();
        pthread_create(&pn[i], NULL, func, &num);
        sleep(3); // 每隔3秒创建一个线程
    }

    //create 5 process
    int sec = 0;
    for (int i = 0; i < 5; i++)
    {
        sec = randomNum();
        status = fork();
        if (status == 0 || status == -1)
        {
            break;
        }
        sleep(5); // 每个5秒生成一个进程
    }
    if (status == -1)
    {
    }

    // 子进程
    else if (status == 0)
    {
        sleep(1);
        alarm(sec);
        printf("son fork pid is %8ld, ppid is %10d, tgid is %12d die after %d s\n", syscall(SYS_gettid), getppid(), getpid(), sec);
        int grandson_pid = fork();
        int sec2 = 0;
        if (grandson_pid == 0)
        {
            sec2 = randomNum();
            printf("gan fork pid is %8ld, ppid is %10d, tgid is %12d die after %d s\n", syscall(SYS_gettid), getppid(), getpid(), sec2);
            alarm(sec2);
            pause();
            exit(0);
        }
        else
        {
            pause();
            wait(NULL);
        }
    }

    else
    {

        for (int i = 0; i < 5; i++)
        {
            pthread_join(pn[i], NULL);
        }

        while (wait(NULL) != -1)
            ;
        // fork() ;
    }
}