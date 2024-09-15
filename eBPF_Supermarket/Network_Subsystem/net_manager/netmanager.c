/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n"
	" - Collects and displays stats from XDP program\n";

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <signal.h>
#include <fcntl.h>
#include "./common/common_params.h"
#include "./common/common_user_bpf_xdp.h"
#include "./common/common_libbpf.h"
#include "common_kern_user.h"
#include "netmanager_kern.skel.h"
static const char *default_filename = "netmanager_kern.o";
static const char *default_progname = "xdp_entry_state";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{"stats",       no_argument,       NULL, 't' },
	 "Show XDP stats"},

	{{"ip-filter",   required_argument, NULL, 'i' },
	 "ip_filter"},

	{{"mac_filter",  required_argument,       NULL, 'm' },
	 "mac_filter"},

	{{"router",      required_argument,       NULL, 'k' },
	 "package_router"},
	
	{{"clear",       no_argument,       NULL, 'n' },
	 "clear_map"},
	
	{{"config",       no_argument,       NULL, 'T' },
	 "config from user to kernel"},

	{{"socketmap_flag",       no_argument,       NULL, 'f' },
	 "socketmap_flag"},
	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";
char pin_dir[PATH_MAX];
char map_filename[PATH_MAX];


static void list_avail_progs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	printf("BPF object (%s) listing available XDP functions\n",
	       bpf_object__name(obj));

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__type(pos) == BPF_PROG_TYPE_XDP)
			printf(" %s\n", bpf_program__name(pos));
	}
}


#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats[XDP_ACTION_MAX];
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print_header()
{
	/* Print stats "header" */
	printf("%-12s\n", "XDP-action");
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i;

	stats_print_header(); /* Print stats "header" */

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++)
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		const char *action = action2str(i);

		rec  = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps     = packets / period;

		bytes   = rec->total.rx_bytes   - prev->total.rx_bytes;
		bps     = (bytes * 8)/ period / 1000000;

		printf(fmt, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes / 1000 , bps,
		       period);
	}
	printf("\n");
}


/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes;
	return true;
}

static void stats_collect(int map_fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	/* Collect all XDP actions stats  */
	__u32 key;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
	}
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */
		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}
}



int unpin_maps(struct bpf_object *bpf_obj)
{
	int err;
	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	return 0;
}

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj)
{
	int err;
	unpin_maps(bpf_obj);
	if (verbose)
		printf(" - Pinning maps in %s/\n", pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}


char *ifname;
int rules_ipv4_map;
int rtcache_map4;
int rules_mac_map;

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
        fprintf(stderr, "ERR: Failed to open map file: %s\n", map_name);
        return -1;
    }
    printf("Opened BPF map\n");
    printf(" - BPF map (bpf_map_type:%d) fd: %d id:%d name:%s"
           " key_size:%d value_size:%d max_entries:%d\n",
           info.type, fd, info.id, info.name,
           info.key_size, info.value_size, info.max_entries);

    return fd;
}


int load_bpf_map(){
    rules_ipv4_map = open_map(ifname, "rules_ipv4_map");
    rtcache_map4 = open_map(ifname, "rtcache_map4");
    rules_mac_map = open_map(ifname, "rules_mac_map");
    // Check if any map failed to open
    if (rules_ipv4_map < 0) {
        fprintf(stderr, "Failed to open rules_ipv4_map\n");
    }
    if (rtcache_map4 < 0) {
        fprintf(stderr, "Failed to open rtcache_map4\n");
    }
    if (rules_mac_map < 0) {
        fprintf(stderr, "Failed to open rules_mac_map\n");
    }

    if (rules_ipv4_map < 0 || rtcache_map4 < 0 || rules_mac_map < 0) {
        fprintf(stderr, "load bpf map error, check device name\n");
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
    bpf_map_delete_batch(rules_mac_map, &keys, &count, &opts);

    return count;
}


int load_handler_router(char * router_file){
    if(!router_file)	
	{
		perror("ERR: loading ROUTER filter is not exist! \n");
		return 1;
	}

    char *path = router_file;
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


int load_handler_ipv4(char* ip_filter_file){
    if(!ip_filter_file)	
	{
		perror("ERR: loading IP filter is not exist! \n");
		return 1;
	}

    char *path = ip_filter_file;
    printf("loading config file:%s\n",path);
    
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    __u16 keys[MAX_RULES];
    struct rules_ipv4 rules[MAX_RULES];

    __u32 i = 1;
    keys[0] = 0;
    char line[256];
	printf("-----------------------------------------------------------------------------------------------\n");
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
		printf("源地址:%u.%u.%u.%u:%u 目的地址:%u.%u.%u.%u:%u 源端口:%d 目的端口:%d 协议类型:%s 策略:%s\n",saddr[0],saddr[1],saddr[2],saddr[3],rules[i].saddr_mask,
		daddr[0],daddr[1],daddr[2],daddr[3],rules[i].daddr_mask,rules[i].sport,rules[i].dport,proto,action);

        i += 1;
    }
	printf("-----------------------------------------------------------------------------------------------\n");
    printf("%d rules loaded\n",i-1);
    rules[0].prev_rule = i - 1;

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);
    clear_map();
    // 使用 libbpf 库中的 bpf_map_update_batch 函数批量更新 BPF 映射。
    // 这个函数用于一次性更新多个键值对，以提高效率。

    // rules_ipv4_map: 要更新的 BPF 映射的文件描述符（FD）。
    // keys: 包含要更新的键（key）的数组。
    // rules: 包含要更新的值的数组。
    // &i: 这是一个指向整数的指针，表示要更新的键值对的数量。在调用函数后，该整数将包含实际更新的键值对数量。
    // &opts: 用于配置更新选项的结构体，这里是通过 DECLARE_LIBBPF_OPTS 宏声明并初始化的。

    // 在这里，代码中的 bpf_map_update_batch 操作的目的是将多个键值对一次性更新到 BPF 映射中。
    // 这样可以通过一次系统调用来完成多个更新操作，提高了效率。

    bpf_map_update_batch(rules_ipv4_map, keys, rules, &i, &opts);

    return 0;   
}


int load_handler_mac(char* mac_filter_file){
    if(!mac_filter_file)	
	{
		perror("ERR: loading MAC filter is not exist! \n");
		return 1;
	}

    char *path = mac_filter_file;
    printf("loading config file:%s\n",path);
    
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
	__u16 keys[MAX_RULES];
    struct rules_mac rules[MAX_RULES];

    __u32 i = 1;
    keys[0] = 0;

    char line[256];
	printf("-----------------------------------------------------------------------------------------------\n");
    
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';

        __u8 src_mac[6];
		__u8 dest_mac[6];
        char action[10];
        sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %s",
           &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5],
		   &dest_mac[0], &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4], &dest_mac[5],
           action);

        //src_mac_u64 = mac_to_u64(src_mac);
		memcpy(rules[i].source, src_mac, ETH_ALEN);
		memcpy(rules[i].dest, dest_mac, ETH_ALEN);

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

		printf("MAC_SRC: %02x:%02x:%02x:%02x:%02x:%02x, MAC_DEST: %02x:%02x:%02x:%02x:%02x:%02x ,Action: %s\n",
                          src_mac[0], src_mac[1], src_mac[2],src_mac[3], src_mac[4], src_mac[5], 
						  dest_mac[0], dest_mac[1], dest_mac[2],dest_mac[3], dest_mac[4], dest_mac[5], 
						  action);

		i += 1;
    }
    
	printf("-----------------------------------------------------------------------------------------------\n");
    printf("%d rules loaded\n",i-1);
    rules[0].prev_rule = i - 1;

    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);
    clear_map();
    bpf_map_update_batch(rules_mac_map, keys, rules, &i, &opts);

    return 0;   
}

static volatile bool exiting = false;

int clear_handler(int argc, char *argv[]){
    int ret = clear_map();
    printf("%d rules are cleared\n", ret-1);
    return 0;
}

static void sig_handler(int signo) { exiting = true; }

int main(int argc, char **argv)
{
	int i;
	int map_fd;
	struct bpf_object *obj;
	struct xdp_program *program;  // XDP程序对象指针
	
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };
	int stats_map_fd;
	int interval = 2;
	int err;  // 错误码
	int len;  // 字符串长度
	char errmsg[1024];  // 错误消息字符串

	// 配置结构体，包括XDP模式、接口索引、是否卸载程序以及程序名称等信息
	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		//.redirect_ifindex   = -1,
		.do_unload   = false,
		.ip_filter   = false,       //ip过滤
		.mac_filter  = false,       //mac过滤
	    .router      = false,       //路由
	    .state       = false,       //会话保持
	    .clear       = false,       //清理
		.socketmap_flag =false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	// 设置默认的BPF ELF对象文件名和BPF程序名称
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progname,  default_progname,  sizeof(cfg.progname));
	/* Cmdline options can change progname */
	// 解析命令行参数，可能会修改程序名称等配置信息
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if(cfg.socketmap_flag)
	{
		struct netmanager_kern *skel;
		signal(SIGINT, sig_handler);
    	signal(SIGTERM, sig_handler);
		skel = netmanager_kern__open();
		int cgroup_fd = open("/sys/fs/cgroup/foo", O_RDONLY);
		if (cgroup_fd < 0) {
			perror("Failed to open cgroup directory");
			return -1;
		}
    	if (!skel) {
    	    fprintf(stderr, "Failed to open BPF skeleton\n");
    	    return 1;
    	}

    	err = netmanager_kern__load(skel);
    	if (err) {
    	    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    	    goto cleanup;
    	}
		err = netmanager_kern__attach(skel);
        if (err) {
            fprintf(stderr, "Failed to attach BPF skeleton\n");
            goto cleanup;
        }
		int sock_ops_prog_fd = bpf_program__fd(skel->progs.bpf_sockmap);
		if (sock_ops_prog_fd < 0) {
			fprintf(stderr, "Invalid sock_ops program fd: %d\n", sock_ops_prog_fd);
			return -1;
		}

		int msg_verdict_prog_fd = bpf_program__fd(skel->progs.bpf_redir);
		if (msg_verdict_prog_fd < 0) {
			fprintf(stderr, "Invalid msg_verdict program fd: %d\n", msg_verdict_prog_fd);
			return -1;
		}

		int sock_ops_map_fd = bpf_map__fd(skel->maps.sock_ops_map);
		if (sock_ops_map_fd < 0) {
			fprintf(stderr, "Invalid sock_ops map fd: %d\n", sock_ops_map_fd);
			return -1;
		}

		err = bpf_prog_attach(sock_ops_prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
		if (err) {
			fprintf(stderr, "Failed to attach bpf_sockmap program: %d\n", err);
			return 1;
		}

		//加载并附加msg_verdict程序
		err = bpf_prog_attach(msg_verdict_prog_fd, sock_ops_map_fd, BPF_SK_MSG_VERDICT, 0);
		if (err) {
			fprintf(stderr, "Failed to attach bpf_redir program: %d\n", err);
			return 1;
		}
		while (!exiting) {
        	sleep(1);
			printf("----1-----\n");
        	/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling perf buffer: %d\n", err);
				break;
			}
    	}
		cleanup:	
    		netmanager_kern__destroy(skel);
    		return err < 0 ? -err : 0;
	}
	/* Required option */
	// 检查是否提供了必需的选项
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	/* Generate pin_dir & map_filename string */
	// 生成pin目录和映射文件名字符串
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}
	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, cfg.ifname, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	// 加载BPF程序并将其附加到XDP
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
    obj = bpf_object__open_file(cfg.filename, &bpf_opts);
    err = libbpf_get_error(obj);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Couldn't open BPF object file %s: %s\n",
            cfg.filename, errmsg);
            return err;
    }


	if (verbose)
		list_avail_progs(obj);
	
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                            .obj = obj,
                            .prog_name = cfg.progname);
	program = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(program);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program %s: %s\n", cfg.progname, errmsg);
		exit(EXIT_FAIL_BPF);
	}

	err = xdp_program__attach(program, cfg.ifindex, cfg.attach_mode, 0);
	if (err) {
		perror("xdp_program__attach");
		exit(err);
	}

	/* do unload */
	// 如果指定了卸载选项，则执行卸载操作
	if (cfg.do_unload) {
		unpin_maps(xdp_program__bpf_obj(program));  // 解除BPF程序固定的映射
		err = do_unload(&cfg);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program %s: %s\n",
				cfg.progname, errmsg);  // 打印卸载错误消息
			return err;
		}

		printf("Success: Unloading XDP prog name: %s\n", cfg.progname);
		return EXIT_OK;; 
	}

	// 如果启用了详细模式，则打印加载的BPF对象文件和程序名称，以及附加的XDP程序的设备信息
	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	// 使用--dev名称作为子目录来导出/固定映射
	err = pin_maps_in_bpf_object(xdp_program__bpf_obj(program));
	if (err) {
		fprintf(stderr, "ERR: pinning maps\n");
		return err;
	}
	ifname = cfg.ifname;


	map_fd = open_bpf_map_file(pin_dir, "print_info_map", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	i = 0;
	bpf_map_update_elem(map_fd, &i, &cfg.print_info, 0);
	

	// 根据不同的选项加载不同的配置文件
    if (cfg.ip_filter) {
		load_bpf_map();
        err = load_handler_ipv4(cfg.ip_filter_file);
        if (err) {
            fprintf(stderr, "ERR: loading IP filter config file\n");
            return err;
        }
    } else if (cfg.mac_filter) {
		load_bpf_map();
        err = load_handler_mac(cfg.mac_filter_file);
        if (err) {
            fprintf(stderr, "ERR: loading MAC filter config file\n");
            return err;
        }
    } else if (cfg.router) {
		load_bpf_map();
        err = load_handler_router(cfg.router_file);
        if (err) {
            fprintf(stderr, "ERR: loading router config file\n");
            return err;
        }
    } else if (cfg.clear) {
		load_bpf_map();
        err = clear_handler(argc - 3, argv + 6);
        if (err) {
            fprintf(stderr, "ERR: clearing maps\n");
            return err;
        }
    }



	map_fd = open_bpf_map_file(pin_dir, "tx_port", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	i = 0;
	bpf_map_update_elem(map_fd, &i, &cfg.ifindex, 0);	
	printf("redirect from ifnum=%d to ifnum=%d\n", cfg.ifindex, cfg.ifindex);

	//打印统计信息
	if (cfg.show_stats) {
		/* Use the --dev name as subdir for finding pinned maps */
		len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
		if (len < 0) {
			fprintf(stderr, "ERR: creating pin dirname\n");
			return EXIT_FAIL_OPTION;
		}

		stats_map_fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
		if (stats_map_fd < 0) {
			return EXIT_FAIL_BPF;
		}

		/* check map info, e.g. datarec is expected size */
		map_expect.key_size    = sizeof(__u32);
		map_expect.value_size  = sizeof(struct datarec);
		map_expect.max_entries = XDP_ACTION_MAX;
		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			return err;
		}
		if (verbose) {
			printf("\nCollecting stats from BPF map\n");
			printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			       " key_size:%d value_size:%d max_entries:%d\n",
			       info.type, info.id, info.name,
			       info.key_size, info.value_size, info.max_entries
			       );
		}

		stats_poll(stats_map_fd, info.type, interval);
		return EXIT_OK;
	}
		
}