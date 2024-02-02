//这段代码主要目的是统计open系统调用的次数
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <bpf/libbpf.h>  
  
#define file_name "syscall_count_kern.o"  
  
int main(void) {  
    // 打开文件为 obj  
    bpf_object *obj = bpf_object__open_file(file_name, NULL);  
    if (libbpf_get_error(obj)) {  
        printf("open file error: %s\n", strerror(errno));  
        return 0;  
    }  
    // 解析elf查找其中的 program  
    bpf_program *prog = bpf_object__find_program_by_name(obj, "trace_enter_open");  
    if (!prog) {  
        printf("not find the program\n");  
        return 0;  
    }  
    // 加载  
    if (bpf_object__load(obj)) {  
        printf("load object error: %s\n", strerror(errno));  
        return 0;  
    }  
    // 建立 map  
    bpf_map *map = bpf_object__find_map_by_name(obj, "data");  
    if (map < 0) {  
        printf("finding map error: %s\n", strerror(errno));  
        return 0;  
    }  
    // attach  
    bpf_link *link = bpf_program__attach(prog);  
    if (libbpf_get_error(link)) {  
        printf("attach failed: %s\n", strerror(errno));  
        return 0;  
    }  
    while (1) {  
        uint32_t key = 0;  
        uint32_t val = 0;  
        // 等待统计数据  
        sleep(5);  
        // 读取  
        if (bpf_map__lookup_elem(map, &key, sizeof(key), &val, sizeof(val), 0) != 0) {  
            printf("loopup error: %s\n", strerror(errno));  
        } else {  
            printf("syscall count: %u\n", val);  
            // 写入  
            val = 0;  
            if (bpf_map__update_elem(map, &key, sizeof(key), &val, sizeof(val), BPF_ANY) != 0) {  
                printf("update error: %s\n", strerror(errno));  
            }  
        }  
    }  
    return 0;  
}