#ifndef __TCPWATCH_H
#define __TCPWATCH_H

// more info ： include/uapi/linux/if_ether.h
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10 /* IP version 6	*/
#endif

struct conn_t {
    const void * sock;
    unsigned int ptid;
    unsigned short family;
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned long long bytes_acked;
    unsigned long long bytes_received;
    unsigned int srtt;
    unsigned long long init_timestamp;
    unsigned long long  duration;
};

#define MAX_PACKET 1000

struct packet_tuple {
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int seq;
    unsigned int ack;
};

struct ktime_info { // us time stamp info
    unsigned long long qdisc_time;
    unsigned long long mac_time;
    unsigned long long ip_time;
    unsigned long long tcp_time;
    unsigned long long app_time;
    unsigned int srtt;
};

struct pack_t{ // us time duration info
    long mac_time;
    long ip_time;
    long tcp_time;
    long seq;
    long ack;
};

struct packs_lru_buf_t {
    struct pack_t packets[MAX_PACKET];
    int begin_index;
    int end_index;
};


#endif /* __TCPWATCH_H */