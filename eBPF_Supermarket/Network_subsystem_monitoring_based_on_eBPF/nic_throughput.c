#include <linux/netdevice.h>
#include <linux/ethtool.h>

#if IFNAMSIZ != 16 
#error "IFNAMSIZ != 16 is not supported"
#endif
#define MAX_QUEUE_NUM 1024

/**
* This union is use to store name of the specified interface
* and read it as two different data types
*/
union name_buf{
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    }name_int;
};

/* data retrieved in tracepoints */
struct queue_data{
    u64 total_pkt_len;
    u32 num_pkt;
};

/* array of length 1 for device name */
BPF_ARRAY(name_map, union name_buf, 1);

/* table for transmit & receive packets */
BPF_HASH(tx_q, u16, struct queue_data, MAX_QUEUE_NUM);
BPF_HASH(rx_q, u16, struct queue_data, MAX_QUEUE_NUM);

static inline int name_filter(struct sk_buff* skb){
    /* get device name from skb */
    union name_buf real_devname;
    struct net_device *dev;

    // source/include/linux/netdevice.h#L172 struct net_device_stats

    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb+offsetof(struct sk_buff, dev)));
    bpf_probe_read(&real_devname, IFNAMSIZ, dev->name);

    int key=0;
    union name_buf *leaf = name_map.lookup(&key);
    if(!leaf){
        return 0;
    }
    if((leaf->name_int).hi != real_devname.name_int.hi || (leaf->name_int).lo != real_devname.name_int.lo){
        return 0;
    }

    return 1;
}

static void updata_data(struct queue_data *data, u64 len){
    data->total_pkt_len += len;
    data->num_pkt ++;
}

// TRACEPOINT_PROBE(category, event)
// https://github.com/torvalds/linux/blob/master/include/trace/events/net.h
TRACEPOINT_PROBE(net, net_dev_start_xmit){
    /* read device name */
    struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
    if(!name_filter(skb)){
        return 0;
    }

    /* update table */
    u16 qid = skb->queue_mapping;
    struct queue_data newdata;
    __builtin_memset(&newdata, 0, sizeof(newdata));
    struct queue_data *data = tx_q.lookup_or_try_init(&qid, &newdata);
    if(!data){
        return 0;
    }
    updata_data(data, skb->len);
    
    return 0;
}

TRACEPOINT_PROBE(net, netif_receive_skb){
    struct sk_buff skb;

    bpf_probe_read(&skb, sizeof(skb), args->skbaddr);
    if(!name_filter(&skb)){
        return 0;
    }

    /* case 1: if the NIC does not support multi-queue feature, there is only
     *         one queue(qid is always 0).
     * case 2: if the NIC supports multi-queue feature, there are several queues
     *         with different qid(from 0 to n-1).
     * The net device driver should mark queue id by API 'skb_record_rx_queue'
     * for a recieved skb, otherwise it should be a BUG(all of the packets are
     * reported as queue 0). For example, virtio net driver is fixed for linux:
     * commit: 133bbb18ab1a2("virtio-net: per-queue RPS config")
     */
    u16 qid = 0;
    if (skb_rx_queue_recorded(&skb))
        qid = skb_get_rx_queue(&skb);

    struct queue_data newdata;
    __builtin_memset(&newdata, 0, sizeof(newdata));
    struct queue_data *data = rx_q.lookup_or_try_init(&qid, &newdata);
    if(!data){
        return 0;
    }
    updata_data(data, skb.len);
    
    return 0;
}
