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
// net_watcher libbpf netfilter

#include "common.bpf.h"

static __always_inline
int submit_nf_time(struct packet_tuple pkt_tuple, struct filtertime *tinfo, int rx)
{
    int time =0;                                     
    struct netfilter *message;
    FILTER
    message = bpf_ringbuf_reserve(&netfilter_rb, sizeof(*message), 0);
    if(!message){
        return 0;
    }

    message->saddr = pkt_tuple.saddr;
    message->daddr =pkt_tuple.daddr;
    message->sport =pkt_tuple.sport;
    message->dport = pkt_tuple.dport;
    message->local_input_time = 0;
    message->pre_routing_time = 0;
    message->local_out_time = 0;
    message->post_routing_time = 0;
    message->forward_time=0;
    message->rx = rx; //收/发/转发方向

    if(rx == 1){
        if(tinfo->time[e_ip_local_deliver_finish] && 
            tinfo->time[e_ip_local_deliver] && 
            tinfo->time[e_ip_rcv])
        {
            message->local_input_time = tinfo->time[e_ip_local_deliver_finish] - 
                                            tinfo->time[e_ip_local_deliver];
            message->pre_routing_time = tinfo->time[e_ip_local_deliver] - 
                                            tinfo->time[e_ip_rcv];             
            if((int)message->local_input_time < 0 || (int)message->pre_routing_time < 0){
                bpf_ringbuf_discard(message, 0);      
                return 0;                                  
            }
        }
    }else{
        if(tinfo->time[e_ip_local_deliver_finish] && 
            tinfo->time[e_ip_local_deliver] &&
            tinfo->time[e_ip_rcv] &&
            tinfo->time[e_ip_forward] && 
            tinfo->time[e_ip_output])
        {
            message->local_input_time = tinfo->time[e_ip_local_deliver_finish] - 
                                            tinfo->time[e_ip_local_deliver];
            message->pre_routing_time = tinfo->time[e_ip_local_deliver] - 
                                            tinfo->time[e_ip_rcv]; 
                                            
            u64 forward_time = tinfo->time[e_ip_output] - tinfo->time[e_ip_forward];             
            
            if((int)forward_time < 0){
                bpf_ringbuf_discard(message, 0);      
                return 0;   
            }
            message->forward_time = forward_time;
            message->rx = 2;
        }
        if(tinfo->time[e_ip_output] &&
            tinfo->time[e_ip_local_out] &&
            tinfo->time[e_ip_finish_output])
        {
            message->local_out_time = tinfo->time[e_ip_output] - 
                                        tinfo->time[e_ip_local_out];
            message->post_routing_time = tinfo->time[e_ip_finish_output] - 
                                            tinfo->time[e_ip_output];
            if((int)message->local_out_time < 0 || (int)message->post_routing_time < 0){
                bpf_ringbuf_discard(message, 0);      
                return 0;   
            }
        }
    }
    bpf_ringbuf_submit(message,0);
    return 0;
}

static __always_inline
int store_nf_time(struct sk_buff *skb, int hook)
{
    if(!net_filter)
        return 0;
    if (skb == NULL) 
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    
    struct filtertime *tinfo, zero = {.init = {0}, .done={0}, .time={0}};
    if(hook == e_ip_rcv || hook == e_ip_local_out){
        tinfo = (struct filtertime *)bpf_map_lookup_or_try_init(&netfilter_time,
                                                            &skb, &zero);  
        if(tinfo == NULL)
            return 0;
        get_pkt_tuple(&tinfo->init, ip, tcp);
    }
    else{
        tinfo = (struct filtertime *)bpf_map_lookup_elem(&netfilter_time, &skb);
        if (tinfo == NULL) {
            return 0;
        }
    }                
    tinfo->time[hook] = bpf_ktime_get_ns() / 1000;
    if(hook == e_ip_local_deliver_finish){
        submit_nf_time(tinfo->init, tinfo, 1);
        bpf_map_delete_elem(&netfilter_time, &skb);
    }

    if(hook == e_ip_finish_output){
        submit_nf_time(tinfo->init, tinfo, 0);
        bpf_map_delete_elem(&netfilter_time, &skb);
    }

    return 0;
}

