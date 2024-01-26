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
int redirect_params;

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
    redirect_params = open_map(ifname, "redirect_params");
    if(src_macs < 0 || redirect_params < 0){
        fprintf(stderr, "load bpf map error,check device name\n");
        return -1;
    }

    return 0;
}



int clear_map(){
    __u16 keys[MAX_SRC_MACS];
    for(int i=0; i<MAX_SRC_MACS; i++){
        keys[i] = i;
    }

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

    __u32 count = MAX_SRC_MACS ;

    bpf_map_delete_batch(src_macs, &keys, &count, &opts);
    bpf_map_delete_batch(redirect_params, &keys, &count, &opts);

    return count;
}

/* filter ethernet frames based on source mac addresses on device */
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

    __u8 src_mac[6];
    __u8 dest_mac[6];
    char line[256];

    clear_map();
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';

       
       	sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5],
            &dest_mac[0], &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4], &dest_mac[5])  ;


        bpf_map_update_elem(redirect_params, src_mac, dest_mac, BPF_ANY);
     
       
    } 
    return 0;  
}


/* filter ethernet frames based on source mac addresses on device */
int filter_ethernet(int drop, const char *ifname, int num_macs, char **macs) {
	/* set xdp program based on drop or pass mode */
	const char *xdp_prog = "filter_ethernet_pass";
	if (drop) {
		xdp_prog = "filter_ethernet_drop";
	}

    printf("loading function:%s\n",xdp_prog);
	

	/* parse macs and add them to map */
	__u8 src_mac[6];
	__u32 value = 1;

    clear_map();
	for (__u32 i = 0; i < num_macs; i++) {
		/* parse mac */
		sscanf(macs[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]) ;

		/* add mac to map */
		
        bpf_map_update_elem(src_macs, src_mac, &value, BPF_ANY);
        
	}
    printf("%d rules loaded\n", num_macs-1);

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

int main(int argc, char *argv[]){ //xacladm load enp1s0 ./conf.d/ipv4.conf
    int ret = 0;

    if(argc < 3){
        print_usage(0);
        return EXIT_FAILURE;
    }

    char pin_dir[PATH_MAX];

    snprintf(pin_dir, PATH_MAX, "%s", pin_basedir);
	printf("map dir: %s\n", pin_dir);

    char *command = argv[1];
    ifname = argv[2];



    load_bpf_map();
    if (strcmp(command, "pass_mac") == 0) {
        //argc - 3: 这是一个整数，表示除去操作类型和接口名称两个参数外，还有多少个额外的参数。
        //argv + 3: 这是一个指向参数数组的指针，指向额外的参数。在这个上下文中，它指向除了操作类型和接口名称之外的其他参数。
        ret = filter_ethernet(0, argv[2], argc - 3, argv + 3);
    } else if(strcmp(command, "drop_mac") == 0) {
        ret = filter_ethernet(1, argv[2], argc - 3, argv + 3);
    } else if(strcmp(command, "load") == 0) {
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