#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

char *ifname;

int rules_ipv4_map;
int rtcache_map4;
int src_macs;

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

int open_map(const char *ifname, const char *map_name){
    int len;
    char pin_dir[PATH_MAX];
    const char *pin_basedir =  "/sys/fs/bpf";
    struct bpf_map_info info = { 0 };

    /* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return -1;
	}

	
    int fd = open_bpf_map_file(pin_dir, map_name, &info);
	if (fd < 0) {
		return -1;
	}
    if (verbose) {
		printf("\nOpened BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) fd: %d id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, fd ,info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}

    return fd;
}


int load_bpf_map(){
    rules_ipv4_map = open_map(ifname, "rules_ipv4_map");
    rtcache_map4 = open_map(ifname, "rtcache_map4");
    src_macs = open_map(ifname, "src_macs");

    if(rules_ipv4_map < 0 || rtcache_map4 < 0 || src_macs < 0){
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
    __u16 keys[MAX_RULES];
    for(int i=0; i<MAX_RULES; i++){
        keys[i] = i;
    }

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

    __u32 count = MAX_RULES - 1;

    bpf_map_delete_batch(rules_ipv4_map, &keys, &count, &opts);
    bpf_map_delete_batch(rtcache_map4, &keys, &count, &opts);
    bpf_map_delete_batch(src_macs, &keys, &count, &opts);

    return count;
}

int load_handler_router(int argc, char *argv[]){
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



int load_handler_ipv4(int argc, char *argv[]){
    if(argc < 1){
        print_usage(1);
        return EXIT_FAILURE;
    }

    char *path = argv[0];
    printf("loading config file:%s\n",path);
    
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    __u16 keys[MAX_RULES];
    struct rules_ipv4 rules[MAX_RULES];

    __u32 i = 1;
    keys[0] = 0;
    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';

        __u8 saddr[4];
        __u8 daddr[4];
        char proto[10];
        char action[10];
        sscanf(line, "%hhu.%hhu.%hhu.%hhu/%hhu %hhu.%hhu.%hhu.%hhu/%hhu %hu %hu %s %s",
           &saddr[0] ,&saddr[1] ,&saddr[2] ,&saddr[3] ,&rules[i].saddr_mask, 
           &daddr[0] ,&daddr[1] ,&daddr[2] ,&daddr[3] ,&rules[i].daddr_mask, 
           &rules[i].sport, &rules[i].dport, proto, action);

        rules[i].saddr = ip_to_u32(saddr);
        rules[i].daddr = ip_to_u32(daddr);

        if(strcmp("TCP", proto) == 0){
            rules[i].ip_proto = IPPROTO_TCP;
        }else if(strcmp("UDP", proto) == 0){
            rules[i].ip_proto = IPPROTO_UDP;
        }else if(strcmp("ICMP", proto) == 0){
            rules[i].ip_proto = IPPROTO_ICMP;
        }else{
            rules[i].ip_proto = 0;
        }

        if(strcmp("ALLOW", action) == 0){
            rules[i].action = XDP_PASS;
        }else if(strcmp("DENY", action) == 0){
            rules[i].action = XDP_DROP;
        }else{
            rules[i].action = XDP_ABORTED;
        }

        rules[i-1].next_rule = i;
        rules[i].prev_rule = i - 1;
        rules[i].next_rule = 0;
        keys[i] = i;

        i += 1;
    }
    printf("%d rules loaded\n",i-1);
    rules[0].prev_rule = i - 1;

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);
    clear_map();

    bpf_map_update_batch(rules_ipv4_map, keys, rules, &i, &opts);

    return 0;   
}


int load_handler_mac(int argc, char *argv[]){
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


    //__u64 src_mac_u64;
    __u32 action_mac;
    char line[256];

    clear_map();
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';

        __u8 src_mac[6];
        char action[10];
        sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %s",
           &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5],
           action);

        //src_mac_u64 = mac_to_u64(src_mac);

           
        if(strcmp("ALLOW", action) == 0){
            action_mac = XDP_PASS;
        }else if(strcmp("DENY", action) == 0){
            action_mac = XDP_DROP;
        }else{
            action_mac = XDP_ABORTED;
        }

        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x, Action: %s\n",
                          src_mac[0], src_mac[1], src_mac[2],
                          src_mac[3], src_mac[4], src_mac[5], action);

        bpf_map_update_elem(src_macs, src_mac, &action_mac, BPF_ANY);
    }
    

    return 0;   
}


int clear_handler(int argc, char *argv[]){
    int ret = clear_map();
    printf("%d rules are cleared\n", ret-1);
    return 0;
}

/*
int parse_cmd(int argc, char *argv[]) {
    int err = 0;

    char *command = argv[1];
    ifname = argv[2];


    //argv[1] 是命令行参数数组 argv 中的第二个元素，即程序运行时传递给程序的第一个参数。
    //argv[2] 是命令行参数数组 argv 中的第三个元素，即程序运行时传递给程序的第二个参数。
    //argv[0] 通常是程序的名称，然后是用户提供的其他参数。
    //以 sudo ./xacladm load docker0 ./conf.d/black_ipv4.conf 为例
    
    sudo 是命令，用于以超级用户权限执行后续的命令。
    ./xacladm 是要执行的程序。
    load 是 ./xacladm 程序的第一个参数，指示程序执行加载操作。
    docker0 是第二个参数，可能是设备名称或其他标识，具体取决于程序的实现。
    ./conf.d/black_ipv4.conf 是第三个参数，可能是配置文件的路径或其他输入数据，也取决于程序的实现。
    

    // 解析命令行参数
    if (strcmp(command, "ip_f") == 0) {

        //argc - 2 表示传递给 load_handler 函数的参数数量，argc - 2 表示从第 3 个参数（argv[3]）开始，
        //而 argv + 3 表示从命令行参数数组中的第四个元素开始的指针，
        //因为前两个参数是程序名称和操作命令。
        err = load_handler_ipv4(argc - 2, argv + 3);
    }
    else if (strcmp(command, "mac_f")) {

        err = load_handler_mac(argc - 2, argv + 3);
    }
    else if (strcmp(command, "rout")) {

        err = load_handler_router(argc - 2, argv + 3);
    }
    else if (strcmp(command, "clear") == 0) {

        err = clear_handler(argc - 2, argv + 3);
    }
    else{
        err = -1;
        goto out_err_parse_cmd;
    }

    return 0;

out_err_parse_cmd:
    // 输出错误信息并返回错误代码
    if(err < 0){
        fprintf(stderr, "[XLB ERR]: parse_cmd(%d)\n", err);
    }
    return -1;
}
*/

// argc 表示命令行参数的数量，argv 是一个指向命令行参数字符串数组的指针。
int main(int argc, char *argv[]){ //xacladm load enp1s0 ./conf.d/ipv4.conf
    int err = 0;

    if(argc < 3){
        print_usage(0);
        return EXIT_FAILURE;
    }


    char *command = argv[1];
    ifname = argv[2];

    if(load_bpf_map()){
        err = -1;
        goto out; // 发生错误则跳转到错误处理部分
    }


    // 解析命令行参数
    if (strcmp(command, "ip_f") == 0) {

        // argc - 2 表示将命令行参数的数量减去2，这可能是为了排除程序名称和command 参数，只留下与接口名称相关的参数。
        //argv + 3 表示将指向命令行参数数组的指针向后移动3个位置，这可能是为了跳过程序名称、command 参数和ifname 参数，直接指向与IPv4配置文件相关的参数。
        //因为前两个参数是程序名称和操作命令。
        err = load_handler_ipv4(argc - 2, argv + 3);
    }
    else if (strcmp(command, "mac_f") == 0) {

        err = load_handler_mac(argc - 2, argv + 3);
    }
    else if (strcmp(command, "rout") == 0) {

        err = load_handler_router(argc - 2, argv + 3);
    }
    else if (strcmp(command, "clear") == 0) {

        err = clear_handler(argc - 2, argv + 3);
    }
    else{
        err = -1;
        goto out;
    }


out:
    // 输出错误信息并返回错误代码
    if(err < 0)
        fprintf(stderr, "[XLB ERR]: main(%d)\n", err);
    return err;
}