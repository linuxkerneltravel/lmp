#ifndef __DELAY_ANALYSIS_H
#define __DELAY_ANALYSIS_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

// more info ： include/uapi/linux/if_ether.h
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

#define AF_INET		2
#define AF_INET6	10	/* IP version 6	*/
#define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)&((__skb)->cb[0]))

static struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct packet_tuple {
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

struct ktime_info {
    u64 qdisc_time;
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
    u64 app_time;
};

struct data_t {
    u64 total_time;
    u64 ip_time;
    u64 tcp_time;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
    /* receive path*/
    u64 mac_timestamp;
    u64 mac_time;
    /* send path */
    u64 qdisc_timestamp;
    u64 qdisc_time;
    /* for ipv4 */
    u32 saddr;
    u32 daddr;
    /* for ipv6 */
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;

    u32 nat_saddr;
    u16 nat_sport;
};

#endif