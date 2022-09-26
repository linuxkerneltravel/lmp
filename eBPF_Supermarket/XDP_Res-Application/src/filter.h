struct metainfo{
   u32 ipproto;
   u32 saddr;
   u32 daddr;
   u16 sport;
   u16 dport;
};


static __always_inline int get_port(void *trans_data, void *data_end,
				     u8 protocol,u16 *sport,u16 *dport)
{
	struct tcphdr *th;
	struct udphdr *uh;

	switch (protocol) {
	case IPPROTO_TCP:
		th = (struct tcphdr *)trans_data;
		if ((void *)th + sizeof(struct tcphdr) > data_end)
			return XDP_DROP;
        *sport = th->source;
        *dport = th->dest;
	case IPPROTO_UDP:
		uh = (struct udphdr *)trans_data;
		if ((void *)uh + sizeof(struct udphdr) > data_end)
			return XDP_DROP;
		*sport = uh->source;
        *dport = uh->dest;
	default:
		*sport = 0;
        *dport = 0;
	}
    return XDP_PASS;
}

static int match_rule(struct metainfo *info){
    u32 result_bit = 0;
    u32 wildcard_u32 = 65535;
    u16 wildcard_u16 = 65535;

    u32 *ipproto_bit = ipproto_map.lookup(&info->ipproto);
    u32 *saddr_bit = saddr_map.lookup(&info->saddr);
    u32 *daddr_bit = daddr_map.lookup(&info->daddr);
    u32 *sport_bit = sport_map.lookup(&info->sport);
    u32 *dport_bit = dport_map.lookup(&info->dport);
    
    if(ipproto_bit == NULL)
        ipproto_bit = ipproto_map.lookup(&wildcard_u32);
    if(saddr_bit == NULL)
        saddr_bit = saddr_map.lookup(&wildcard_u32);
    if(daddr_bit == NULL)
        daddr_bit = daddr_map.lookup(&wildcard_u32);   
    if(sport_bit == NULL)
        sport_bit = sport_map.lookup(&wildcard_u16);
    if(dport_bit == NULL)
        dport_bit = dport_map.lookup(&wildcard_u16);

    if(ipproto_bit != NULL){
        if(*ipproto_bit != 0)
            result_bit = *ipproto_bit;
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

    if(result_bit == 0)
        return XDP_PASS;
    result_bit &= -result_bit; //get the prio rule
    int *action = action_map.lookup(&result_bit);
        if(action != NULL)
            return *action;
    
    return XDP_PASS;
}