#ifndef __TCPWATCH_H
#define __TCPWATCH_H

#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10 /* IP version 6	*/
#endif

#define MAX_COMM 16

struct conn_t {
    void *sock;
    char comm[MAX_COMM];
    unsigned int ptid;
    unsigned short family;
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int tcp_backlog;
    unsigned int max_tcp_backlog;
    unsigned long long bytes_acked;
    unsigned long long bytes_received;

    unsigned int snd_cwnd;
    unsigned int snd_ssthresh;
    unsigned int sndbuf;
    unsigned int sk_wmem_queued;

    unsigned int srtt;
    unsigned long long init_timestamp;
    unsigned long long duration;
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

struct pack_t { // us time duration info
    unsigned long long mac_time;
    unsigned long long ip_time;
    unsigned long long tcp_time;
    unsigned int seq;
    unsigned int ack;
    char comm[MAX_COMM];
    const void *sock;
    int rx; // rx packet(1) or tx packet(0)
};

#endif /* __TCPWATCH_H */