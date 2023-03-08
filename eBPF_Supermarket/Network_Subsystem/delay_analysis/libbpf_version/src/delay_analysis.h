#ifndef __DELAY_ANALYSIS_H
#define __DELAY_ANALYSIS_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

struct packet_tuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

struct flow_tuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct ktime_info {
    u64 qdisc_time;
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
    u64 app_time;
};

struct data_t {
    u8 dir;
    u64 total_time;
    u64 qdisc_timestamp;
    u64 qdisc_time;
    u64 mac_timestamp;
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
    u32 saddr;
    u32 daddr;
    u32 nat_saddr;
    u16 nat_sport;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

#endif