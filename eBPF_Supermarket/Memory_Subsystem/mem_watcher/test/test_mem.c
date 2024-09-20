#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>

#define ALLOC_SIZE_SMALL 4
#define ALLOC_SIZE_MEDIUM 64
#define ALLOC_SIZE_LARGE 1024

static struct env {
    bool overall_leak_test;
    bool mem_leak;
    bool mem_unleak;
} env = {
    .overall_leak_test = false,
    .mem_leak = false,
    .mem_unleak = false,
};

const char argp_program_doc[] ="mem_watcher test.\n";

static const struct argp_option opts[] = {
    { NULL, 0, NULL, 0, "Memory Management Options:", 1 },
    { "overall-test", 'o', NULL, 0, "Perform overall memory test", 2 },
    { "detect-leak", 'l', NULL, 0, "Detect memory leaks", 3 },
    { "no-leak", 'n', NULL, 0, "No memory leaks expected", 3 },
    { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help", 0 },
    { NULL, 0, NULL, 0, NULL, 0 }
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    (void)arg; 
	switch (key) {
		case 'o':
            env.overall_leak_test = true;
            break;
		case 'l':
            env.mem_leak = true;
            break;
		case 'n':
            env.mem_unleak = true;
            break;
		case 'h':
				argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
				break;
      default:
         return ARGP_ERR_UNKNOWN;
	}	
	return 0;
}

// 模拟一些处理，通过写入分配的内存
static void process_data(void *ptr, int size) {
    memset(ptr, 0, size);
}

// 分配内存并处理数据
static void * alloc_v3(int alloc_size) {
    void *ptr = malloc(alloc_size);
    if (ptr) {
        process_data(ptr, alloc_size / 3);
    }
    return ptr;
}

// 分配内存并处理数据
static void * alloc_v2(int alloc_size) {
    void *ptr = alloc_v3(alloc_size);
    if (ptr) {
        process_data(ptr, alloc_size / 4);
    }
    return ptr;
}

// 分配内存并处理数据
static void * alloc_v1(int alloc_size) {
    void *ptr = alloc_v2(alloc_size);
    if (ptr) {
        process_data(ptr, alloc_size / 5);
    }
    return ptr;
}

// 演示内存泄漏
static void leak_memory() {
    void *ptr = malloc(ALLOC_SIZE_LARGE);
    // 故意不释放 ptr 以制造内存泄漏
    process_data(ptr, ALLOC_SIZE_LARGE);
}

static void mem_leak_process() {
    // 引入一些间歇性的内存泄漏
    void *ptr = NULL;
    int i = 0;
    for (i = 0; ; i++) {
        if (i % 5 == 0) {
            leak_memory();
        }
        sleep(1);
    }
}

static void mem_unleak_process(){
    void *ptr = NULL;
    int i = 0;

    for (i = 0; ; i++) {
        int alloc_size = (i % 3 == 0) ? ALLOC_SIZE_SMALL : (i % 3 == 1) ? ALLOC_SIZE_MEDIUM : ALLOC_SIZE_LARGE;

        ptr = alloc_v1(alloc_size);
        if (!ptr) {
            perror("alloc_v1 失败");
            exit(EXIT_FAILURE);
        }

        void *ptr2 = malloc(alloc_size);
        if (!ptr2) {
            perror("malloc 失败");
            free(ptr);
            exit(EXIT_FAILURE);
        }

        process_data(ptr2, alloc_size);

        sleep(1);
        free(ptr);

        sleep(2);
        free(ptr2);
    }
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

    if (env.overall_leak_test) {
        // 打印当前进程的进程号（PID）
        pid_t pid = getpid();
        printf("当前进程的进程号（PID）: %d\n", pid);
        if (env.mem_leak) {
            printf("正在进行内存泄漏检测...\n");
            mem_leak_process();
        }
        if (env.mem_unleak) {
            printf("正在进行无内存泄漏测试...\n");
            mem_unleak_process();
        }
    }

    return 0;
}
