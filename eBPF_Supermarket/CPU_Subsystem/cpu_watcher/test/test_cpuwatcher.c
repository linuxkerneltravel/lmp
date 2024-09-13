#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <argp.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/fcntl.h>
#include <string.h>

#define gettid() syscall(__NR_gettid)

static struct env {
   bool sar_test;
   bool cs_delay_test;
   bool sc_delay_test;
   bool mq_delay_test;
   bool preempt_test;
   bool schedule_test;
   bool mutrace_test1;
   bool mutrace_test2;
} env = {
   .sar_test = false,
   .cs_delay_test = false,
   .sc_delay_test = false,
   .mq_delay_test = false,
   .preempt_test = false,
   .schedule_test = false,
   .mutrace_test1 = false,
   .mutrace_test2 = false,
};

const char argp_program_doc[] ="To test cpu_watcher.\n";

static const struct argp_option opts[] = {
   { "sar", 's', NULL, 0, "To test sar", 0 },
   { "cs_delay", 'c', NULL, 0, "To test cs_delay", 0 },
   { "sc_delay", 'S', NULL, 0, "To test sc_delay", 0 },
   { "mq_delay", 'm', NULL, 0, "To test mq_delay", 0 },
   { "preempt_delay", 'p', NULL, 0, "To test preempt_delay", 0 },
   { "schedule_delay", 'd', NULL, 0, "To test schedule_delay", 0 },
   { "mu_trace_kernel", 'x', NULL, 0, "To test kernel mutrace", 0 },
   { "mu_trace_user", 'u', NULL, 0, "To test user mutrace", 0 },
   { "all", 'a', NULL, 0, "To test all", 0 },
   { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help", 0 },
   {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    (void)arg; 
	switch (key) {
		case 'a':
				env.sar_test = true;
				env.cs_delay_test = true;
				env.mq_delay_test = true;
				env.preempt_test = true;
                env.sc_delay_test = true;
                env.schedule_test = true;
				break;
		case 's':
				env.sar_test = true;
				break;
		case 'c':
            env.cs_delay_test = true;
            break;
        case 'S':
            env.sc_delay_test = true;
            break;
		case 'm':
				env.mq_delay_test = true;
            break;
        case 'p':
            env.preempt_test = true;
            break;
        case 'd':
            env.schedule_test = true;
            break;
        case 'x':
            env.mutrace_test1 = true;
            break;
        case 'u':
            env.mutrace_test2 = true;
            break;
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
      default:
         return ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

void *schedule_stress_test(void *arg) {
    (void)arg;
    while (1) {
        sched_yield(); // 调度函数
    }
    return NULL;
}

void start_schedule_stress_test(int num_threads) {
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, schedule_stress_test, NULL);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);
}

void *func(void *arg)
{
   (void)arg;
   int tpid;
   tpid = gettid();
   printf("新线程pid:%d,睡眠3s后退出\n",tpid);
   sleep(3);
   printf("新线程退出\n");
   return NULL;
}

void input_pid() {
    int stop;
    int pid = getpid();
    printf("test_proc进程的PID:【%d】\n", pid);
    printf("输入任意数字继续程序的运行:");
    scanf("%d", &stop); // 使用时将其取消注释
    printf("程序开始执行...\n");
    printf("\n");
}

void *mutex_test_thread(void *arg) {
    pthread_mutex_t *mutex = (pthread_mutex_t *)arg;
    uintptr_t mutex_addr = (uintptr_t)mutex;  // 获取互斥锁的地址

    for (int i = 0; i < 10; i++) {
        pthread_mutex_lock(mutex);
        printf("Thread %ld (mutex address: %lu) acquired the mutex\n", 
               pthread_self(), (unsigned long)mutex_addr);
        usleep(rand() % 1000); 
        pthread_mutex_unlock(mutex);
        printf("Thread %ld (mutex address: %lu) released the mutex\n", 
               pthread_self(), (unsigned long)mutex_addr);
        usleep(rand() % 1000);
    }

    return NULL;
}

void start_mutex_test(int num_threads) {
    pthread_mutex_t mutex;
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));

    pthread_mutex_init(&mutex, NULL);

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, mutex_test_thread, &mutex);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&mutex);
    free(threads);
}


int main(int argc, char **argv){
    int err;
    static const struct argp argp = {
    	.options = opts,
    	.parser = parse_arg,
    	.doc = argp_program_doc,
    };

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
    	return err;

    if(env.sar_test){
        printf("SAR_TEST----------------------------------------------\n");
        //SAR功能测试逻辑：系统上执行混合压力测试，包括4个顺序读写硬盘线程、4个IO操作线程，持续15秒,观察加压前后的变化。
        char *argvv[] = { "/usr/bin/stress-ng", "--hdd", "4", "--hdd-opts", "wr-seq,rd-seq", "--io", "4",  "--timeout", "15s", "--metrics-brief", NULL };
        char *envp[] = { "PATH=/bin", NULL };
        printf("SAR功能测试逻辑：系统上执行混合压力测试，包括4个顺序读写硬盘线程、4个IO操作线程和4个UDP网络操作线程，持续15秒,观察加压前后的变化\n");
        printf("执行指令 stress-ng --hdd 4 --hdd-opts wr-seq,rd-seq --io 4 --udp 4 --timeout 15s --metrics-brief\n");
        execve("/usr/bin/stress-ng", argvv, envp);
        perror("execve");
        printf("\n");
    }

    if(env.cs_delay_test){
         printf("CS_DELAY_TEST----------------------------------------------\n");
         //CS_DELAY功能测试逻辑：无限循环的线程函数，不断调用 sched_yield() 来放弃 CPU 使用权，模拟高调度负载。
         start_schedule_stress_test(10); // 创建10个线程进行调度压力测试
    }

    if(env.sc_delay_test){
         printf("SC_DELAY_TEST----------------------------------------------\n");
         //SC_DELAY功能测试逻辑：创建多个系统调用，观察其变化
          const int num_iterations = 1000000; // 系统调用的迭代次数
        for (int i = 0; i < num_iterations; i++) {
            getpid();     // 获取进程ID
            getppid();    // 获取父进程ID
            time(NULL);   // 获取当前时间
            syscall(SYS_gettid); // 获取线程ID
        }
        printf("系统调用压力测试完成。\n");
    }

    if(env.mq_delay_test){
    /*mq_delay的测试代码*/
        input_pid(); // 在mq_delay_test中调用
        system("./sender & ./receiver");
        sleep(60);
        system("^Z");
    }

    if(env.preempt_test){
         printf("PREEMPT_TEST----------------------------------------------\n");
        //PREEMPT功能测试逻辑：无限循环的线程函数，不断调用 sched_yield() 来放弃 CPU 使用权，模拟高调度负载。
         start_schedule_stress_test(10); // 创建10个线程进行调度压力测试
    }

    if(env.schedule_test){
        printf("SCHEDULE_TEST----------------------------------------------\n");
        // 调度延迟测试逻辑：创建线程执行 sysbench --threads=32 --time=10 cpu run，观察加压前后的变化
        char *argvv[] = { "/usr/bin/sysbench", "--threads=32", "--time=10", "cpu", "run", NULL };
        char *envp[] = { "PATH=/bin", NULL };
        printf("调度延迟测试逻辑：\n");
        printf("执行指令 sysbench --threads=32 --time=10 cpu run\n");
        execve("/usr/bin/sysbench", argvv, envp);
        perror("execve");
        printf("\n");
    }

    if(env.mutrace_test1){
         printf("MUTRACE_KERNEL_TEST----------------------------------------------\n");
        //内核态互斥锁功能测试逻辑：系统上执行混合压力测试，包括4个顺序读写硬盘线程、4个IO操作线程，持续15秒,观察加压前后的变化。
        char *argvv[] = { "/usr/bin/stress-ng", "--hdd", "4", "--hdd-opts", "wr-seq,rd-seq", "--io", "4",  "--timeout", "15s", "--metrics-brief", NULL };
        char *envp[] = { "PATH=/bin", NULL };
        printf("MUTRACE功能测试逻辑：系统上执行混合压力测试，包括4个顺序读写硬盘线程、4个IO操作线程和4个UDP网络操作线程，持续15秒,观察加压前后的变化\n");
        printf("执行指令 stress-ng --hdd 4 --hdd-opts wr-seq,rd-seq --io 4 --udp 4 --timeout 15s --metrics-brief\n");
        execve("/usr/bin/stress-ng", argvv, envp);
        perror("execve");
        printf("\n");
    }


    if(env.mutrace_test2){
        printf("MUTRACE_USER_TEST----------------------------------------------\n");
        printf("测试场景: 创建多个线程，每个线程反复加锁和解锁同一个互斥锁，观察互斥锁的争用情况\n");
        start_mutex_test(10); // 创建10个线程进行互斥锁测试
        printf("测试结束\n");
        printf("\n");
        
    }
    return 0;
}
