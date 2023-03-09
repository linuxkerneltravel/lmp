#include "vmlinux.h"
#include "maps.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "delay_analysis.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10800);
	__type(key, struct packet_tuple);
	__type(value, struct ktime_info);
} in_timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10800);
	__type(key, struct packet_tuple);
	__type(value, struct ktime_info);
} out_timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;
const volatile int sampling = 0;
const volatile int _is_ipv6 = 0;    // default is ipv4
const volatile int _is_send  = 0;   // default is receive path

#define SAMPLING  if(sampling){ if (((pkt_tuple.seq + pkt_tuple.ack + BPF_CORE_READ(skb,len)) << (32-sampling) >> (32-sampling)) != ((0x01 << sampling) - 1)) { return 0;}}
#define FILTER_DPORT if(filter_dport){if (pkt_tuple.dport != filter_dport) { return 0; }}
#define FILTER_SPORT if(filter_sport){if (pkt_tuple.sport != filter_sport) { return 0; }}

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
    return (struct tcphdr *)((BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,transport_header)));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb){
    return (struct iphdr *)(BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,network_header));
}

static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb){
    return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
}

static void get_pkt_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip, struct tcphdr *tcp){
    pkt_tuple->saddr = BPF_CORE_READ(ip,saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip,daddr);
    u16 sport = BPF_CORE_READ(tcp,source);
    u16 dport = BPF_CORE_READ(tcp,dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp,seq);
    u32 ack = BPF_CORE_READ(tcp,ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    pkt_tuple->ack = __bpf_ntohl(ack);
} 

static void get_pkt_tuple_v6(struct packet_tuple *pkt_tuple, struct ipv6hdr *ip6h, struct tcphdr *tcp){
    bpf_probe_read_kernel(&pkt_tuple->saddr_v6, sizeof(pkt_tuple->saddr_v6), &ip6h->saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&pkt_tuple->daddr_v6, sizeof(pkt_tuple->daddr_v6), &ip6h->daddr.in6_u.u6_addr32);
    u16 sport = BPF_CORE_READ(tcp, source);
    u16 dport = BPF_CORE_READ(tcp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    pkt_tuple->dport = __bpf_ntohs(dport);

    u32 seq = BPF_CORE_READ(tcp, seq);
    u32 ack = BPF_CORE_READ(tcp, ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    pkt_tuple->ack = __bpf_ntohl(ack);
} 

/*!
in_ipv4:
    kprobe/eth_type_trans
    kprobe/ip_rcv_core.isra.0
    kprobe/tcp_v4_rcv
    kprobe/skb_copy_datagram_iter

in_ipv6:
    kprobe/eth_type_trans
    kprobe/ip6_rcv_core.isra.0
    kprobe/tcp_v6_rcv
    kprobe/skb_copy_datagram_iter

out_ipv4:
    kprobe/tcp_sendmsg
    kprobe/ip_queue_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit

out_ipv6:
    kprobe/tcp_sendmsg
    kprobe/inet6_csk_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit

*/
/************************************************ receive path ****************************************/
/** in ipv4 && ipv6 */
SEC("kprobe/eth_type_trans")
int BPF_KPROBE(eth_type_trans, struct sk_buff *skb){
    /* reveive path */
    if (!_is_send) {
         const struct ethhdr* eth = (struct ethhdr*)BPF_CORE_READ(skb,data);
        u16 protocol = BPF_CORE_READ(eth, h_proto); 
        /** ipv4 */
        if (!_is_ipv6) {
            if (protocol == __bpf_ntohs(ETH_P_IP)){ // Protocol is IP
                struct iphdr *ip = (struct iphdr *)(BPF_CORE_READ(skb,data) + 14);
                // TODO options in hdr
                struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb,data) + sizeof(struct iphdr) + 14);
                struct packet_tuple pkt_tuple = {};
                get_pkt_tuple(&pkt_tuple, ip, tcp);
                
                SAMPLING
                FILTER_DPORT
                FILTER_SPORT
                
                struct ktime_info *tinfo, zero={}; 
                
                tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&in_timestamps,&pkt_tuple, &zero);
                if (tinfo == NULL){
                    return 0;
                }
                tinfo->mac_time = bpf_ktime_get_ns();
            }
        }
        else {
            if (protocol == __bpf_htons(ETH_P_IPV6)){ // Protocol is IPV6  
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(BPF_CORE_READ(skb,data) + 14);
            struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb,data) + sizeof(struct ipv6hdr) + 14);
            struct packet_tuple pkt_tuple = {};
            get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);
            
            SAMPLING
            FILTER_DPORT
            FILTER_SPORT
            
            struct ktime_info *tinfo, zero={}; 
            
            tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&in_timestamps,&pkt_tuple, &zero);
            if (tinfo == NULL){
                return 0;
            }
            tinfo->mac_time = bpf_ktime_get_ns();
            }
        }
    }
    return 0;
}

/** in only ipv4 */
SEC("kprobe/ip_rcv_core.isra.0")
int BPF_KPROBE(ip_rcv_core,struct sk_buff *skb){
    if (!_is_send) {
        if (!_is_ipv6) {
            if (skb == NULL)
                return 0;
            struct iphdr *ip = skb_to_iphdr(skb);
            struct tcphdr *tcp = skb_to_tcphdr(skb);
            struct packet_tuple pkt_tuple = {};
            get_pkt_tuple(&pkt_tuple, ip, tcp);

            SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            struct ktime_info *tinfo;
            if ((tinfo = bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->ip_time = bpf_ktime_get_ns();
        }
    }
    return 0;
}

/**in only ipv4 */
SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv,struct sk_buff *skb){
    if (!_is_send) {
        if (!_is_ipv6) {
            if (skb == NULL)
                return 0;
            struct iphdr *ip = skb_to_iphdr(skb);
            struct tcphdr *tcp = skb_to_tcphdr(skb);
            struct packet_tuple pkt_tuple = {};
            get_pkt_tuple(&pkt_tuple, ip, tcp);

            SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            struct ktime_info *tinfo;
            if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->tcp_time = bpf_ktime_get_ns();
        }
    }
    return 0;
}

/** in only ipv6 */
SEC("kprobe/ip6_rcv_core.isra.0")
int BPF_KPROBE(ip6_rcv_core,struct sk_buff *skb){
    if (!_is_send) {
        if (_is_ipv6) {
             if (skb == NULL)
                return 0;
            struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
            struct tcphdr *tcp = skb_to_tcphdr(skb);
            struct packet_tuple pkt_tuple = {};
            get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

            SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            struct ktime_info *tinfo;
            if ((tinfo = bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->ip_time = bpf_ktime_get_ns();

        }
    }   
    return 0;
}

/** in only ipv6 */
SEC("kprobe/tcp_v6_rcv")
int BPF_KPROBE(tcp_v6_rcv,struct sk_buff *skb){
    if (!_is_send) {
        if (_is_ipv6) {
            if (skb == NULL)
                return 0;
            struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
            struct tcphdr *tcp = skb_to_tcphdr(skb);
            struct packet_tuple pkt_tuple = {};
            get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

            SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            struct ktime_info *tinfo;
            if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->tcp_time = bpf_ktime_get_ns();
        }
    }
    return 0;
}

/** in ipv4 && ipv6 */
SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter,struct sk_buff *skb){
    if (!_is_send) {
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        struct packet_tuple pkt_tuple = {};
        struct ktime_info *tinfo;
        /** ipv4 */
        if (!_is_ipv6) {
            if (skb == NULL)
                return 0;
            struct iphdr *ip = skb_to_iphdr(skb);
            get_pkt_tuple(&pkt_tuple, ip, tcp);

            SAMPLING
            FILTER_DPORT
            FILTER_SPORT
            
            if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->app_time = bpf_ktime_get_ns();         
        }
        /** ipv6 */
        else {
            if (skb == NULL)
                return 0;
            struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
            get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

            SAMPLING
            FILTER_DPORT
            FILTER_SPORT
            
            if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->app_time = bpf_ktime_get_ns();
        }
        /* data handle, both ipv4 and ipv6 */
        struct data_t *data;
        data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
            return 0;
        data->mac_timestamp = tinfo->mac_time;
        data->total_time = tinfo->app_time - tinfo->mac_time;
        data->mac_time = tinfo->ip_time - tinfo->mac_time;
        data->ip_time = tinfo->tcp_time - tinfo->ip_time;
        data->tcp_time = tinfo->app_time - tinfo->tcp_time;
        data->sport = pkt_tuple.sport;
        data->dport = pkt_tuple.dport;
        data->seq = pkt_tuple.seq;
        data->ack = pkt_tuple.ack;
        if (!_is_ipv6) {
            data->saddr = pkt_tuple.saddr;
            data->daddr = pkt_tuple.daddr;
        }
        else {
            data->saddr_v6 = pkt_tuple.saddr_v6;
            data->daddr_v6 = pkt_tuple.daddr_v6;
        }
        bpf_map_delete_elem(&in_timestamps,&pkt_tuple);
        bpf_ringbuf_submit(data, 0);
    }
    return 0;
}
/***************************************** end of receive path ****************************************/

/************************************************ send path *******************************************/
/*!
* \brief: 获取数据包进入TCP层时刻的时间戳, 发送tcp层起始点
*         out ipv4 && ipv6
*/
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (_is_send) {
        u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        struct ktime_info *tinfo, zero = {};
        struct packet_tuple pkt_tuple = {};
        if (!_is_ipv6) {
            /** ipv4 */
            if (family == AF_INET) {
                u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
                pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
                pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
                pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
                pkt_tuple.dport = __bpf_ntohs(dport);

                u32 snd_nxt = BPF_CORE_READ(tcp_sk(sk), snd_nxt);
                u32 rcv_nxt = BPF_CORE_READ(tcp_sk(sk), rcv_nxt);
                pkt_tuple.seq = snd_nxt;
                pkt_tuple.ack = rcv_nxt;
                //__bpf_printk("tcp_sendmsg \n");
                //__bpf_printk("pkt_tuple.ack   = %d \n",  pkt_tuple.ack);

                //SAMPLING
                FILTER_DPORT
                FILTER_SPORT

                //bpf_map_lookup_or_try_init(&flows, &pkt_tuple, &ftuple);
                tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&out_timestamps, &pkt_tuple, &zero);
                if (tinfo == NULL) {
                    return 0;
                }
                tinfo->tcp_time = bpf_ktime_get_ns();   
            }

        }
        else {
            /** ipv6 */
            if (family == AF_INET6) {
            bpf_probe_read_kernel(&pkt_tuple.saddr_v6,
                    sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
                        &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

            bpf_probe_read_kernel(&pkt_tuple.daddr_v6,
                    sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
                        &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            
            pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
            u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
            pkt_tuple.dport = __bpf_ntohs(dport);

            u32 snd_nxt = BPF_CORE_READ(tcp_sk(sk), snd_nxt);
            u32 rcv_nxt = BPF_CORE_READ(tcp_sk(sk), rcv_nxt);
            pkt_tuple.seq = snd_nxt;
            pkt_tuple.ack = rcv_nxt;
            //__bpf_printk("tcp_sendmsg \n");
            //__bpf_printk("pkt_tuple.ack   = %d \n",  pkt_tuple.ack);

            //SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&out_timestamps, &pkt_tuple, &zero);
            if (tinfo == NULL) {
                return 0;
            }
            tinfo->tcp_time = bpf_ktime_get_ns();   
            }
        }
    }  
    return 0;
}

/*!
* \brief: 获取数据包进入IP层时刻的时间戳
* tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip, tcp)获取ip段的数据
        out only ipv4
*/
SEC("kprobe/ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit, struct sock *sk, struct sk_buff *skb)
{   
    if (_is_send) {
        u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        if (family == AF_INET) {
            struct packet_tuple pkt_tuple = {};
            struct tcphdr *tcp = skb_to_tcphdr(skb);
            u16 dport;
            u32 seq, ack;
            pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
            dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
            pkt_tuple.dport = __bpf_ntohs(dport);
            seq = BPF_CORE_READ(tcp, seq);
            ack = BPF_CORE_READ(tcp, ack_seq);
            pkt_tuple.seq = __bpf_ntohl(seq);
            pkt_tuple.ack = __bpf_ntohl(ack);
            /* for debug 
            __bpf_printk("ip_queue_xmit, sk \n");
            __bpf_printk("pkt_tuple.saddr = %d \n",  pkt_tuple.saddr);
            __bpf_printk("pkt_tuple.daddr = %d \n",  pkt_tuple.daddr);
            __bpf_printk("pkt_tuple.sport = %d \n",  pkt_tuple.sport);
            __bpf_printk("pkt_tuple.dport = %d \n",  pkt_tuple.dport);
            __bpf_printk("pkt_tuple.seq   = %d \n",  pkt_tuple.seq);
            __bpf_printk("pkt_tuple.ack   = %d \n",  pkt_tuple.ack);
            */
            //SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            struct ktime_info *tinfo;
            if ((tinfo = bpf_map_lookup_elem(&out_timestamps, &pkt_tuple)) == NULL){
                // debug info look : cat /sys/kernel/debug/tracing/trace_pipe, root mode
                __bpf_printk("Hash search failed, please check!\n");
                return 0;
            }
            tinfo->ip_time = bpf_ktime_get_ns();
        }
    } 
    return 0;
};

/*!
* \brief: 获取数据包进入IP层时刻的时间戳
* tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip, tcp)获取ip段的数据
        out only ipv6
*/
SEC("kprobe/inet6_csk_xmit")
int BPF_KPROBE(inet6_csk_xmit, struct sock *sk, struct sk_buff *skb)
{
    if (_is_send) {
        u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        if (family == AF_INET6) {
            struct packet_tuple pkt_tuple = {};
            struct tcphdr *tcp = skb_to_tcphdr(skb);
            u16 dport;
            u32 seq, ack;

            bpf_probe_read_kernel(&pkt_tuple.saddr_v6,
                    sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
                        &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

            bpf_probe_read_kernel(&pkt_tuple.daddr_v6,
                    sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
                        &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

            pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
            dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
            pkt_tuple.dport = __bpf_ntohs(dport);
            seq = BPF_CORE_READ(tcp, seq);
            ack = BPF_CORE_READ(tcp, ack_seq);
            pkt_tuple.seq = __bpf_ntohl(seq);
            pkt_tuple.ack = __bpf_ntohl(ack);
            /* for debug 
            __bpf_printk("ip_queue_xmit, sk \n");
            __bpf_printk("pkt_tuple.saddr = %d \n",  pkt_tuple.saddr);
            __bpf_printk("pkt_tuple.daddr = %d \n",  pkt_tuple.daddr);
            __bpf_printk("pkt_tuple.sport = %d \n",  pkt_tuple.sport);
            __bpf_printk("pkt_tuple.dport = %d \n",  pkt_tuple.dport);
            __bpf_printk("pkt_tuple.seq   = %d \n",  pkt_tuple.seq);
            __bpf_printk("pkt_tuple.ack   = %d \n",  pkt_tuple.ack);
            */
            //SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            struct ktime_info *tinfo;
            if ((tinfo = bpf_map_lookup_elem(&out_timestamps, &pkt_tuple)) == NULL){
                // debug info look : cat /sys/kernel/debug/tracing/trace_pipe, root mode
                __bpf_printk("Hash search failed, please check!\n");
                return 0;
            }
            tinfo->ip_time = bpf_ktime_get_ns();
        }
    }
    return 0;
};

/*!
* \brief: 获取数据包进入数据链路层时刻的时间戳
    out ipv4 && ipv6
*/
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(dev_queue_xmit, struct sk_buff *skb)
{
    if (_is_send) {
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        struct packet_tuple pkt_tuple = {};
        struct ktime_info *tinfo;
        if (!_is_ipv6) {
            /** ipv4 */
            struct iphdr *ip = skb_to_iphdr(skb);
            get_pkt_tuple(&pkt_tuple, ip, tcp);

            //SAMPLING
            FILTER_DPORT
            FILTER_SPORT  

            if ((tinfo = bpf_map_lookup_elem(&out_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->mac_time = bpf_ktime_get_ns();
        }
        else {
            /** ipv6 */
            struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
            get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

            //SAMPLING
            FILTER_DPORT
            FILTER_SPORT  

            if ((tinfo = bpf_map_lookup_elem(&out_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->mac_time = bpf_ktime_get_ns();
        }
    }
    return 0;
};

/*!
* \brief: 获取数据包发送时刻的时间戳
    out ipv4 && ipv6
*/
SEC("kprobe/dev_hard_start_xmit")
int BPF_KPROBE(dev_hard_start_xmit, struct sk_buff *skb)
{
    if (_is_send) {
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        struct packet_tuple pkt_tuple = {};
        struct ktime_info *tinfo;
        if (!_is_ipv6) {
            /** ipv4 */
            struct iphdr *ip = skb_to_iphdr(skb);
            get_pkt_tuple(&pkt_tuple, ip, tcp);

            //SAMPLING
            FILTER_DPORT
            FILTER_SPORT
            
            if ((tinfo =  bpf_map_lookup_elem(&out_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->qdisc_time = bpf_ktime_get_ns(); 
        }
        else {
            /** ipv6 */
            struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
            get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

            //SAMPLING
            FILTER_DPORT
            FILTER_SPORT

            if ((tinfo =  bpf_map_lookup_elem(&out_timestamps,&pkt_tuple)) == NULL){
                return 0;
            }
            tinfo->qdisc_time = bpf_ktime_get_ns();
        }
        u16 nat_sport = 0;
        nat_sport = BPF_CORE_READ(tcp,source);
         // data handle both ipv4 and ipv6
        struct data_t *data;
        data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
            return 0;
        data->total_time = tinfo->qdisc_time - tinfo->tcp_time;
        data->qdisc_timestamp = tinfo->qdisc_time;
        data->qdisc_time = tinfo->qdisc_time - tinfo->mac_time;
        data->ip_time = tinfo->mac_time - tinfo->ip_time;
        data->tcp_time = tinfo->ip_time - tinfo->tcp_time;
        if (_is_ipv6) {
            data->saddr_v6 = pkt_tuple.saddr_v6;
            data->daddr_v6 = pkt_tuple.daddr_v6;
        }
        else {
            data->saddr = pkt_tuple.saddr;
            data->daddr = pkt_tuple.daddr;
        }
        
        data->sport = pkt_tuple.sport;
        data->dport = pkt_tuple.dport;
        data->seq = pkt_tuple.seq;
        data->ack = pkt_tuple.ack;

        //data->nat_saddr = BPF_CORE_READ(ip, saddr);
        data->nat_sport = __bpf_ntohs(nat_sport);

        bpf_map_delete_elem(&out_timestamps,&pkt_tuple);
        bpf_ringbuf_submit(data, 0);
    }
    return 0;
};

/***************************************** end of send path *******************************************/