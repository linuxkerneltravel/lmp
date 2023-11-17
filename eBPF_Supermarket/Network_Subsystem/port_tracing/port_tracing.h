#ifndef __PORT_TRACING_H
#define __PORT_TRACING_H

struct cwnd_data{
    int pid;
    int  sum;
    unsigned int sadder;
    unsigned int dadder;
    unsigned int port;
    char comm[20];
 
};

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))
#endif