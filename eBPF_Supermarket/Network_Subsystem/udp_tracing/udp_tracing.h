#ifndef __UDP_TRACING_H
#define __UDP_TRACING_H

struct cwnd_data{
    int pid;
    unsigned long long send;
    unsigned long long recv;
    unsigned int saddr;
    unsigned int daddr;
    unsigned int sport;
    unsigned int dport;
    unsigned int total;
    char comm[20];
 
};

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))
#endif