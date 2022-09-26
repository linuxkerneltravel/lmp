BPF_HASH(ipproto_map, u32, u32);
BPF_HASH(saddr_map, u32, u32);
BPF_HASH(daddr_map, u32, u32);
BPF_HASH(sport_map, u16, u32);
BPF_HASH(dport_map, u16, u32);
BPF_HASH(action_map,u32, u32);
#ifdef COUNT
BPF_HASH(count, u32, u64);
#endif