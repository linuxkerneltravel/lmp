```c
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
```

IPv4 Checksum Calculate:

```c
int csum = 0;
ipv4_csum(ip, sizeof(struct iphdr), &csum);
```

Tcp Checksum Calculate:

```c
__u64 tcp_csum = 0 ;
__u32 tcplen = bpf_ntohs(ip->tot_len) - ip->ihl * 4;
ipv4_l4_csum((void *)tcp, tcplen, &tcp_csum, iph,data_end);
```

