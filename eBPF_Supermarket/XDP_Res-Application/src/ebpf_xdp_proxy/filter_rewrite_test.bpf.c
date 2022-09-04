#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

BPF_HASH(ipproto_map, u32, u32);
BPF_HASH(saddr_map, u32, u32);
BPF_HASH(daddr_map, u32, u32);
BPF_HASH(sport_map, u16, u32);
BPF_HASH(dport_map, u16, u32);
BPF_HASH(action_map,u32, u32);
BPF_HASH(redirect_map,u32, u32);

struct metainfo{
   u32 ipproto;
   u32 saddr;
   u32 daddr;
   u16 sport;
   u16 dport;
};

#define MAX_TCP_LENGTH 1480


static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}


static __always_inline void ipv4_csum(void *data_start, int data_size,
				      __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}



static __always_inline void ipv4_l4_csum(void *data_start, __u32 data_size,
                                __u64 *csum, struct iphdr *iph,
								void *data_end) {
	__u32 tmp = 0;
	*csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
	*csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);

	tmp = bpf_htonl((__u32)(iph->protocol));
	*csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
	tmp = bpf_htonl((__u32)(data_size));
	*csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);	

   
	// Compute checksum from scratch by a bounded loop
	__u16 *buf = data_start;
	for (int i = 0; i < MAX_TCP_LENGTH; i += 2) {
		if ((void *)(buf + 1) > data_end) {
			break;
		}
		*csum += *buf;
		buf++;
	}

		if ((void *)(buf + 1) <= data_end) {
			*csum += *(__u8 *)buf;
		}
      
   
	*csum = csum_fold_helper(*csum);
   
}


static int match_rule(struct metainfo *info){
   int result_bit = 0;
   int *ipproto_bit = ipproto_map.lookup(&info->ipproto);
   int *saddr_bit = saddr_map.lookup(&info->saddr);
   int *daddr_bit = daddr_map.lookup(&info->daddr);
   int *sport_bit = sport_map.lookup(&info->sport);
   int *dport_bit = dport_map.lookup(&info->dport);
   if(ipproto_bit != NULL){
      if(*ipproto_bit != 0){
         if(result_bit == 0){
            result_bit = *ipproto_bit;
         }
         else
            result_bit = result_bit & *ipproto_bit;
      }
   }
   if(saddr_bit != NULL){
      if(*saddr_bit != 0){
         if(result_bit == 0)
            result_bit = *saddr_bit;
         else
            result_bit = result_bit & *saddr_bit;
      }
   }
   if(daddr_bit != NULL){ 
      if(*daddr_bit != 0){     
         if(result_bit == 0)
            result_bit = *daddr_bit;
         else
            result_bit = result_bit & *daddr_bit;
      }
   }
   if(sport_bit != NULL){
      if(*sport_bit != 0){
         if(result_bit == 0)
            result_bit = *sport_bit;
         else
            result_bit = result_bit & *sport_bit;
      }
   }
   if(dport_bit != NULL){
      if(*dport_bit != 0){
         if(result_bit == 0)
            result_bit = *dport_bit;
         else
            result_bit = result_bit & *dport_bit;
      }
   }
   //if(info->ipproto == IPPROTO_ICMP)
   //   bpf_trace_printk("ipproto:%d,result_bit:%d",info->ipproto,result_bit);
   if(result_bit == 0)
      return XDP_PASS;
   result_bit &= -result_bit; //get the prio rule
   int *action = action_map.lookup(&result_bit);
      if(action != NULL){
         return *action;
      }

   return XDP_PASS;
}
 
int xdp_filter(struct xdp_md *ctx) {

    //从xdp程序的上下文参数获取数据包的起始地址和终止地址
   void *data = (void *)(long)ctx->data;
   void *data_end = (void *)(long)ctx->data_end;
   int offset = 0;

   struct metainfo info;

   //以太网头部
   struct ethhdr *eth = (struct ethhdr *)data;
   //ip头部
   struct iphdr *ip;
   //以太网头部偏移量
   offset = sizeof(struct ethhdr);
   //异常数据包，丢弃
   if(data + offset > data_end){
    return XDP_DROP;
   }
   ip = data + offset;
   offset += sizeof(struct iphdr);
   //异常数据包，丢弃
   if(data + offset > data_end){
    return XDP_DROP;
   }
   //从ip头部获取信息
   info.ipproto = ip->protocol;
   info.saddr = ip->saddr;
   info.daddr = ip->daddr;
   if(info.ipproto == IPPROTO_TCP){
      struct tcphdr *tcp = data + offset;
      offset += sizeof(struct tcphdr);
      if(data + offset > data_end)
         return XDP_DROP;
      //从tcp头部获取信息
      info.sport = tcp->source;
      info.dport = tcp->dest;
      int action = match_rule(&info);
      if(action == XDP_DROP)
         return XDP_DROP;
      if(action == XDP_REDIRECT){
         if(tcp->dest == bpf_htons(3000)){
            //ip->daddr = bpf_htonl(0xAC110002);
            //tcp->dest = bpf_htons(80);
            bpf_trace_printk("old:%x",tcp->check);
            ip->check = 0;
            int csum = 0;
            ipv4_csum(ip, sizeof(struct iphdr), &csum);
            ip->check = csum;
            
            u64 tcp_csum;
            int tcplen = bpf_ntohs(ip->tot_len) - ip->ihl * 4;
            tcp->check = 0;
            tcp_csum = 0;		
            ipv4_l4_csum((void *)tcp, (__u32)tcplen, &tcp_csum, ip,data_end);
            tcp->check = tcp_csum;
            bpf_trace_printk("new:%x",tcp->check);
            
            return XDP_PASS;
            //int result = bpf_redirect(4,0);
            //bpf_trace_printk("bpf_redir%d",result);
            //return result;
         }
      }
   }
   else if(info.ipproto == IPPROTO_UDP){
      struct udphdr *udp = data + offset;
      offset += sizeof(struct udphdr);
      if(data + offset > data_end)
         return XDP_DROP;
      //从udp头部获取信息
      info.sport = udp->source;
      info.dport = udp->dest;
      return match_rule(&info);
   }
   else{
      info.sport = 0;
      info.dport = 0;
      return match_rule(&info);
   }
   return XDP_PASS;
}
