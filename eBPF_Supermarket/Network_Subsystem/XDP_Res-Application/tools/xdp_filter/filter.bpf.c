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

struct metainfo{
   u32 ipproto;
   u32 saddr;
   u32 daddr;
   u16 sport;
   u16 dport;
};

static int match_rule(struct metainfo *info){
   int result_bit = 0;
   u32 wildcard_u32 = 65535;
   u16 wildcard_u16 = 65535;
   int *ipproto_bit = ipproto_map.lookup(&info->ipproto);
   int *saddr_bit = saddr_map.lookup(&info->saddr);
   int *daddr_bit = daddr_map.lookup(&info->daddr);
   int *sport_bit = sport_map.lookup(&info->sport);
   int *dport_bit = dport_map.lookup(&info->dport);
   if(ipproto_bit == NULL)
      ipproto_bit = ipproto_map.lookup(&wildcard_u32);
   if(ipproto_bit != NULL){
      if(*ipproto_bit != 0){
         if(result_bit == 0){
            result_bit = *ipproto_bit;
         }
         else
            result_bit = result_bit & *ipproto_bit;
      }
   }
   if(saddr_bit == NULL)
      saddr_bit = saddr_map.lookup(&wildcard_u32);
   if(saddr_bit != NULL){
      if(*saddr_bit != 0){
         if(result_bit == 0)
            result_bit = *saddr_bit;
         else
            result_bit = result_bit & *saddr_bit;
      }
   }

   if(daddr_bit == NULL)
      daddr_bit = daddr_map.lookup(&wildcard_u32);   
   if(daddr_bit != NULL){ 
      if(*daddr_bit != 0){     
         if(result_bit == 0)
            result_bit = *daddr_bit;
         else
            result_bit = result_bit & *daddr_bit;
      }
   }

   if(sport_bit == NULL)
      sport_bit = sport_map.lookup(&wildcard_u16);
   if(sport_bit != NULL){
      if(*sport_bit != 0){
         if(result_bit == 0)
            result_bit = *sport_bit;
         else
            result_bit = result_bit & *sport_bit;
      }
   }

   if(dport_bit == NULL)
      dport_bit = dport_map.lookup(&wildcard_u16);
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
      if(action != NULL)
         return *action;

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
      return match_rule(&info);
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
