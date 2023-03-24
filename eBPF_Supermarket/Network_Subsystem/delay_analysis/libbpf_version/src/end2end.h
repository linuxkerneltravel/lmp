#ifndef __END2END_H
#define __END2END_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

#define ETH_P_IP	0x0800

#define max_trace_func 10

struct packet_tuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

struct pkt_time_info {
    u64 time[max_trace_func];
};

#endif