#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#include <bpf/bpf.h>

#include "map_common.h"
#include "common_kern_user.h"

char *ifname;
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

int load_bpf_map(){
    src_macs = open_map(ifname, "src_macs");
    if(src_macs < 0){
        fprintf(stderr, "load bpf map error,check device name\n");
        return -1;
    }

    return 0;
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

    __u32 count = MAX_RULES ;

    bpf_map_delete_batch(src_macs, &keys, &count, &opts);

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

        bpf_map_update_elem(src_macs, src_mac, &action_mac, BPF_ANY);
    }
    

    return 0;   
}



int clear_handler(int argc, char *argv[]){
    int ret = clear_map();
    printf("%d rules are cleared\n", ret-1);
    return 0;
}


int main(int argc, char *argv[]){ //xacladm load enp1s0 ./conf.d/ipv4.conf
    int ret = 0;

    if(argc < 3){
        print_usage(0);
        return EXIT_FAILURE;
    }

    char *command = argv[1];
    ifname = argv[2];

    load_bpf_map();
    if (strcmp(command, "load") == 0) {
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