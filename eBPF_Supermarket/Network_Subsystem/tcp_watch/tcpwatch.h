// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: blown.away@qq.com
//
// tcpwatch libbpf 内核<->用户 传递信息相关结构体

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

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

#define MAX_COMM 16

struct conn_t {
    int pid;               // pid
    void *sock;            // 此tcp连接的 socket 地址
    char comm[MAX_COMM];   // 此tcp连接的 command
    unsigned int ptid;     // 此tcp连接的ptid
    unsigned short family; // v6(AF_INET6) or v4(AF_INET)
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int tcp_backlog;          // backlog
    unsigned int max_tcp_backlog;      // max_backlog
    unsigned long long bytes_acked;    // 已确认的字节数
    unsigned long long bytes_received; // 已接收的字节数

    unsigned int snd_cwnd;       // 拥塞窗口大小
    unsigned int snd_ssthresh;   // 慢启动阈值
    unsigned int sndbuf;         // 发送缓冲区大小(byte)
    unsigned int sk_wmem_queued; // 已使用的发送缓冲区

    unsigned int srtt;                 // 平滑往返时间
    unsigned long long init_timestamp; // 建立连接时间戳
    unsigned long long duration;       // 连接已建立时长
};

#define MAX_PACKET 1000
#define MAX_HTTP_HEADER 256

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

struct pack_t {
    int err;                     // no err(0) invalid seq(1) invalid checksum(2)
    unsigned long long mac_time; // mac layer 处理时间(us)
    unsigned long long ip_time;  // ip layer 处理时间(us)
    unsigned long long tcp_time; // tcp layer 处理时间(us)
    unsigned int seq;            // the seq num of packet
    unsigned int ack;            // the ack num of packet
    unsigned char data[MAX_HTTP_HEADER]; // 用户层数据
    const void *sock;                    // 此包tcp连接的 socket 指针
    int rx;                              // rx packet(1) or tx packet(0)
};

#endif /* __TCPWATCH_H */