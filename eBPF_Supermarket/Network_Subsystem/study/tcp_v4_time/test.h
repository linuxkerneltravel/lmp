#ifndef __TEST_H
#define __TEST_H

struct cwnd_data{
    int pid;
    int current_time;
    int start_seq;
    int end_seq;
 
};
#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))
#endif