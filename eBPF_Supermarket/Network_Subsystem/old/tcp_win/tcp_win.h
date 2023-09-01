#ifndef __TCP_WIN_H
#define __TCP_WIN_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

struct cwnd_data{
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u32 state;
    u32 snd_cwnd;
    u32 snd_ssthresh;
    u32 sndbuf;
    u32 sk_wmem_queued;
};

#endif