#ifndef __TCPWATCH_H
#define __TCPWATCH_H

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10 /* IP version 6	*/
#endif

struct conn_t {
    const void * sock;
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

#endif /* __TCPWATCH_H */