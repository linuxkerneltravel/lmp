#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#include <bpf/bpf.h>

#include "map_common.h"
#include "common_kern_user.h"


char *ifname;

int rtcache_map4;

int print_usage(int id){
    switch(id){
        case 0:
            fprintf(stderr, "Usage: <command> <arg1> <arg2>\n");
            break;
        default:
            break;
    };

    return 0;
}


int load_bpf_map(){
    rtcache_map4 = open_map(ifname, "rtcache_map4");
    if(rtcache_map4 < 0){
        fprintf(stderr, "load bpf map error,check device name\n");
        return -1;
    }

    return 0;
}


static __u32 ip_to_u32(__u8 *ip_u8) {
    __u32 ip_u32 = 0;
    ip_u32 = (ip_u8[0]<<24) | (ip_u8[1]<<16) | (ip_u8[2]<<8) | (ip_u8[3]);
    //printf("%hhu.%hhu.%hhu.%hhu,%u\n",ip_u8[0],ip_u8[1],ip_u8[2],ip_u8[3],ip_u32);
    return ip_u32;
}


int clear_map(){
    __u8 keys[MAX_RULES];
    for(int i=0; i<MAX_RULES; i++){
        keys[i] = i;
    }

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

    __u32 count = MAX_RULES - 1;

    bpf_map_delete_batch(rtcache_map4, &keys, &count, &opts);

    return count;
}


int load_handler(int argc, char *argv[]){
    if(argc < 1){
        print_usage(1);
        return EXIT_FAILURE;
    }

    char *path = argv[0];
    printf("loading config file:%s\n",path);
    
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }


    __u32 keys[MAX_RULES];
    struct rt_item rules[MAX_RULES];

    __u32 i = 0;
    keys[0] = 0;
    char line[MAX_RULES];

    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';

        __u8 saddr[4];
        __u8 eth_source[ETH_ALEN];
        __u8 eth_dest[ETH_ALEN];
        

        sscanf(line, "%hhu.%hhu.%hhu.%hhu %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhx:%hhx:%hhx:%hhx:%hhx:%hhx" ,
            &saddr[0] ,&saddr[1] ,&saddr[2] ,&saddr[3],
            &eth_source[0], &eth_source[1], &eth_source[2], &eth_source[3], &eth_source[4], &eth_source[5], 
            &eth_dest[0], &eth_dest[1], &eth_dest[2], &eth_dest[3], &eth_dest[4], &eth_dest[5]);

        rules[i].saddr = ip_to_u32(saddr);
        memcpy(rules[i].eth_source, eth_source, ETH_ALEN);
        memcpy(rules[i].eth_dest, eth_dest, ETH_ALEN);

        keys[i] = i;
        i += 1;
       
    } 
    printf("%d rules loaded\n",i);

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);
    clear_map();

    bpf_map_update_batch(rtcache_map4, keys, rules, &i, &opts);
    return 0;  
}

int clear_handler(int argc, char *argv[]){
    int ret = clear_map();
    printf("%d rules are cleared\n", ret-1);
    return 0;
}


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";


//main 的两个参数 argc 和 argv 分别表示命令行参数的数量和内容。
int main(int argc, char *argv[]){

	int ret = 0;

    if(argc < 3){
        print_usage(0);
        return EXIT_FAILURE;
    }

	char pin_dir[PATH_MAX];

    snprintf(pin_dir, PATH_MAX, "%s", pin_basedir);
	printf("map dir: %s\n", pin_dir);

    //argv[1] 是命令行参数数组 argv 中的第二个元素，即程序运行时传递给程序的第一个参数。
    //argv[2] 是命令行参数数组 argv 中的第三个元素，即程序运行时传递给程序的第二个参数。
    //argv[0] 通常是程序的名称，然后是用户提供的其他参数。
    //以 sudo ./xacladm load docker0 ./conf.d/black_ipv4.conf 为例
    /*
    sudo 是命令，用于以超级用户权限执行后续的命令。
    ./xacladm 是要执行的程序。
    load 是 ./xacladm 程序的第一个参数，指示程序执行加载操作。
    docker0 是第二个参数，可能是设备名称或其他标识，具体取决于程序的实现。
    ./conf.d/black_ipv4.conf 是第三个参数，可能是配置文件的路径或其他输入数据，也取决于程序的实现。
    */
	char *command = argv[1];
    ifname = argv[2];

    load_bpf_map();
    if (strcmp(command, "load") == 0) {
        //argc - 2 表示传递给 load_handler 函数的参数数量，argc - 2 表示从第 3 个参数（argv[3]）开始，
        //而 argv + 3 表示从命令行参数数组中的第四个元素开始的指针，
        //因为前两个参数是程序名称和操作命令。
        ret = load_handler(argc - 2, argv + 3);
    } else if (strcmp(command, "clear") == 0) {
        ret = clear_handler(argc - 2, argv + 3);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(0);
        return EXIT_FAILURE;
    }

    return ret;
}


