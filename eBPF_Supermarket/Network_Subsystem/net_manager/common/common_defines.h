#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <xdp/libxdp.h>


#define FILE_MAXSIZE 128 
#define IF_NAMESIZE 16 

struct config {
	enum xdp_attach_mode attach_mode;
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	__u32 prog_id;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progname[32];
	char src_mac[18];
	char dest_mac[18];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
	bool unload_all;
	bool show_stats;  // 数据统计
	bool ip_filter;   //ip过滤
	bool mac_filter;  //mac过滤
	bool router;  //路由
	bool state;       //会话保持
	bool clear;       //清理
	char *ip_filter_file;
	char ip_filter_file_buf[FILE_MAXSIZE];
	char *mac_filter_file;
	char mac_filter_file_buf[FILE_MAXSIZE];
	char *router_file;
	char router_file_buf[FILE_MAXSIZE];
	bool print_info;
	bool socketmap_flag;
};

/* Defined in common_params.o */
extern int verbose;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */
