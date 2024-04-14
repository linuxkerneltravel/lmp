### 从virtio-net网卡驱动看 XDP 转发原理

为了弄清楚 XDP 在内核中究竟是怎么执行的，于是从网卡的收包函数开始看（以virtio_net网卡驱动为例）。

在`virtnet_alloc_queues`初始化中，会调用`netif_napi_add`注册收报`poll`函数`virtnet_poll`。

```c
/* drivers/net/virtio_net.c */

static int virtnet_poll(struct napi_struct *napi, int budget)
{
	struct receive_queue *rq =
		container_of(napi, struct receive_queue, napi);
	struct virtnet_info *vi = rq->vq->vdev->priv;
	struct send_queue *sq;
	unsigned int received;
	unsigned int xdp_xmit = 0; //

	virtnet_poll_cleantx(rq);

	received = virtnet_receive(rq, budget, &xdp_xmit);

	/* Out of packets? */
	if (received < budget)
		virtqueue_napi_complete(napi, rq->vq, received);

	if (xdp_xmit & VIRTIO_XDP_REDIR)
		xdp_do_flush();

	if (xdp_xmit & VIRTIO_XDP_TX) {
		sq = virtnet_xdp_get_sq(vi);
		if (virtqueue_kick_prepare(sq->vq) && virtqueue_notify(sq->vq)) {
			u64_stats_update_begin(&sq->stats.syncp);
			sq->stats.kicks++;
			u64_stats_update_end(&sq->stats.syncp);
		}
		virtnet_xdp_put_sq(vi, sq);
	}

	return received;
}
```

在`virtnet_poll`函数中，注意到一个叫`xdp_xmit`的变量，从名字上可以看出，这个和xdp密切相关，并且可以看到后面的处理逻辑与该变量的值有关，进一步分析代码，可以看出`xdp_xmit`的指针传递给了`virtnet_receive`函数。

```c
/* drivers/net/virtio_net.c */

static int virtnet_receive(struct receive_queue *rq, int budget,
			   unsigned int *xdp_xmit)
{
	struct virtnet_info *vi = rq->vq->vdev->priv;
	struct virtnet_rq_stats stats = {};
	unsigned int len;
	void *buf;
	int i;

	if (!vi->big_packets || vi->mergeable_rx_bufs) {
		void *ctx;

		while (stats.packets < budget &&
		       (buf = virtqueue_get_buf_ctx(rq->vq, &len, &ctx))) {
			receive_buf(vi, rq, buf, len, ctx, xdp_xmit, &stats);
			stats.packets++;
		}
	} else {
		while (stats.packets < budget &&
		       (buf = virtqueue_get_buf(rq->vq, &len)) != NULL) {
			receive_buf(vi, rq, buf, len, NULL, xdp_xmit, &stats);
			stats.packets++;
		}
	}

	...

	return stats.packets;
}
```

进一步跟踪`xdp_xmit`，可以看出它的指针进一步交给了`receive_buf`。

```c
/* drivers/net/virtio_net.c */

static void receive_buf(struct virtnet_info *vi, struct receive_queue *rq,
			void *buf, unsigned int len, void **ctx,
			unsigned int *xdp_xmit,
			struct virtnet_rq_stats *stats)
{
	struct net_device *dev = vi->dev;
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;

	...

	if (vi->mergeable_rx_bufs)
		skb = receive_mergeable(dev, vi, rq, buf, ctx, len, xdp_xmit,
					stats);
	else if (vi->big_packets)
		skb = receive_big(dev, vi, rq, buf, len, stats);
	else
		skb = receive_small(dev, vi, rq, buf, ctx, len, xdp_xmit, stats);

	if (unlikely(!skb))
		return;

	...
}
```

在`receive_buf`中，通过判断是否以mergeable的形式收包，进入到不同的处理函数，这里以`receive_mergeable`为例。

```C
/* drivers/net/virtio_net.c */

static struct sk_buff *receive_mergeable(struct net_device *dev,
					 struct virtnet_info *vi,
					 struct receive_queue *rq,
					 void *buf,
					 void *ctx,
					 unsigned int len,
					 unsigned int *xdp_xmit,
					 struct virtnet_rq_stats *stats)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr = buf;
	u16 num_buf = virtio16_to_cpu(vi->vdev, hdr->num_buffers);
	struct page *page = virt_to_head_page(buf);
	int offset = buf - page_address(page);
	struct sk_buff *head_skb, *curr_skb;
	struct bpf_prog *xdp_prog;
	unsigned int truesize = mergeable_ctx_to_truesize(ctx);
	unsigned int headroom = mergeable_ctx_to_headroom(ctx);
	unsigned int metasize = 0;
	unsigned int frame_sz;
	int err;

	head_skb = NULL;
	stats->bytes += len - vi->hdr_len;

	..

	if (likely(!vi->xdp_enabled)) { 
		xdp_prog = NULL;
		goto skip_xdp;
	}

	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (xdp_prog) {
		struct xdp_frame *xdpf;
		struct page *xdp_page;
		struct xdp_buff xdp;
		void *data;
		u32 act;

		/* Transient failure which in theory could occur if
		 * in-flight packets from before XDP was enabled reach
		 * the receive path after XDP is loaded.
		 */
		if (unlikely(hdr->hdr.gso_type))
			goto err_xdp;

		/* Buffers with headroom use PAGE_SIZE as alloc size,
		 * see add_recvbuf_mergeable() + get_mergeable_buf_len()
		 */
		frame_sz = headroom ? PAGE_SIZE : truesize;

		/* This happens when rx buffer size is underestimated
		 * or headroom is not enough because of the buffer
		 * was refilled before XDP is set. This should only
		 * happen for the first several packets, so we don't
		 * care much about its performance.
		 */
		if (unlikely(num_buf > 1 ||
			     headroom < virtnet_get_headroom(vi))) {
			/* linearize data for XDP */
			xdp_page = xdp_linearize_page(rq, &num_buf,
						      page, offset,
						      VIRTIO_XDP_HEADROOM,
						      &len);
			frame_sz = PAGE_SIZE;

			if (!xdp_page)
				goto err_xdp;
			offset = VIRTIO_XDP_HEADROOM;
		} else {
			xdp_page = page;
		}

		/* Allow consuming headroom but reserve enough space to push
		 * the descriptor on if we get an XDP_TX return code.
		 */
		data = page_address(xdp_page) + offset;
		xdp_init_buff(&xdp, frame_sz - vi->hdr_len, &rq->xdp_rxq);
		xdp_prepare_buff(&xdp, data - VIRTIO_XDP_HEADROOM + vi->hdr_len,
				 VIRTIO_XDP_HEADROOM, len - vi->hdr_len, true);

		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		stats->xdp_packets++;

		switch (act) {
		case XDP_PASS:
			metasize = xdp.data - xdp.data_meta;

			/* recalculate offset to account for any header
			 * adjustments and minus the metasize to copy the
			 * metadata in page_to_skb(). Note other cases do not
			 * build an skb and avoid using offset
			 */
			offset = xdp.data - page_address(xdp_page) -
				 vi->hdr_len - metasize;

			/* recalculate len if xdp.data, xdp.data_end or
			 * xdp.data_meta were adjusted
			 */
			len = xdp.data_end - xdp.data + vi->hdr_len + metasize;

			/* recalculate headroom if xdp.data or xdp_data_meta
			 * were adjusted, note that offset should always point
			 * to the start of the reserved bytes for virtio_net
			 * header which are followed by xdp.data, that means
			 * that offset is equal to the headroom (when buf is
			 * starting at the beginning of the page, otherwise
			 * there is a base offset inside the page) but it's used
			 * with a different starting point (buf start) than
			 * xdp.data (buf start + vnet hdr size). If xdp.data or
			 * data_meta were adjusted by the xdp prog then the
			 * headroom size has changed and so has the offset, we
			 * can use data_hard_start, which points at buf start +
			 * vnet hdr size, to calculate the new headroom and use
			 * it later to compute buf start in page_to_skb()
			 */
			headroom = xdp.data - xdp.data_hard_start - metasize;

			/* We can only create skb based on xdp_page. */
			if (unlikely(xdp_page != page)) {
				rcu_read_unlock();
				put_page(page);
				head_skb = page_to_skb(vi, rq, xdp_page, offset,
						       len, PAGE_SIZE, false,
						       metasize,
						       headroom);
				return head_skb;
			}
			break;
		case XDP_TX:
			stats->xdp_tx++;
			xdpf = xdp_convert_buff_to_frame(&xdp);
			if (unlikely(!xdpf)) {
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			err = virtnet_xdp_xmit(dev, 1, &xdpf, 0);
			if (unlikely(!err)) {
				xdp_return_frame_rx_napi(xdpf);
			} else if (unlikely(err < 0)) {
				trace_xdp_exception(vi->dev, xdp_prog, act);
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_TX;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			stats->xdp_redirects++;
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err) {
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(vi->dev, xdp_prog, act);
			fallthrough;
		case XDP_ABORTED:
			trace_xdp_exception(vi->dev, xdp_prog, act);
			fallthrough;
		case XDP_DROP:
			if (unlikely(xdp_page != page))
				__free_pages(xdp_page, 0);
			goto err_xdp;
		}
	}
	rcu_read_unlock();

skip_xdp:
	head_skb = page_to_skb(vi, rq, page, offset, len, truesize, !xdp_prog,
			       metasize, headroom);
	...
xdp_xmit:
	return NULL;
}
```

到了这个函数中，终于找到了处理 XDP 程序的关键逻辑。

```c
if (likely(!vi->xdp_enabled)) { //是否开启了xdp，若未开启直接跳转到skip_xdp
		xdp_prog = NULL;
		goto skip_xdp;
	}
```

这里判断是否开启了 XDP ，若果未开启，则直接跳转到`skip_xdp`，开始构建`sk_buff`。

```c
xdp_prog = rcu_dereference(rq->xdp_prog);
```

从`rq_>xdp_prog`处读取 XDP 程序。`rq`是什么呢？其类型为`struct receive_queue`

```c
/* drivers/net/virtio_net.c */

/* Internal representation of a receive virtqueue */
struct receive_queue {
	/* Virtqueue associated with this receive_queue */
	struct virtqueue *vq;

	struct napi_struct napi;

	struct bpf_prog __rcu *xdp_prog;

	struct virtnet_rq_stats stats;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Min single buffer size for mergeable buffers case. */
	unsigned int min_buf_len;

	/* Name of this receive queue: input.$index */
	char name[40];

	struct xdp_rxq_info xdp_rxq;
};
```

`rq`是virtio-net的接收队列。包含了进行实际数据交换的环形队列`virtqueue`、以及挂载的 XDP 程序等信息。

```c
/* include/net/xdp.h */

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz; /* frame size to deduce data_hard_end/reserved tailroom*/
	u32 flags; /* supported values defined in xdp_buff_flags */
};

```

接下来是填充`xdp_buff`结构体中的信息

```c
xdp_init_buff(&xdp, frame_sz - vi->hdr_len, &rq->xdp_rxq);
xdp_prepare_buff(&xdp, data - VIRTIO_XDP_HEADROOM + vi->hdr_len,
				 VIRTIO_XDP_HEADROOM, len - vi->hdr_len, true);
```

```c
/* include/net/xdp.h */

static __always_inline void
xdp_init_buff(struct xdp_buff *xdp, u32 frame_sz, struct xdp_rxq_info *rxq)
{
	xdp->frame_sz = frame_sz;
	xdp->rxq = rxq;
	xdp->flags = 0;
}

static __always_inline void
xdp_prepare_buff(struct xdp_buff *xdp, unsigned char *hard_start,
		 int headroom, int data_len, const bool meta_valid)
{
	unsigned char *data = hard_start + headroom;

	xdp->data_hard_start = hard_start;
	xdp->data = data;
	xdp->data_end = data + data_len;
	xdp->data_meta = meta_valid ? data : data + 1;
}
```

这些参数就是 XDP 程序中处理 packet 所需的关键信息，如`data`、`data_end`这些

接下来通过`bpf_prog_run_xdp`运行 eBPF XDP程序

```c
act = bpf_prog_run_xdp(xdp_prog, &xdp);
```

我们所需的返回值 action 就是程序的返回值

```c
/* include/linux/filter.h */

static __always_inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog,
					    struct xdp_buff *xdp)
{
	/* Driver XDP hooks are invoked within a single NAPI poll cycle and thus
	 * under local_bh_disable(), which provides the needed RCU protection
	 * for accessing map entries.
	 */
	u32 act = __bpf_prog_run(prog, xdp, BPF_DISPATCHER_FUNC(xdp));

	if (static_branch_unlikely(&bpf_master_redirect_enabled_key)) { //bond模式下
		if (act == XDP_TX && netif_is_bond_slave(xdp->rxq->dev))
			act = xdp_master_redirect(xdp);
	}

	return act;
}
```

接下来`switch (act)`根据 action 的不同去执行不同的处理逻辑。以XDP_REDIRECT为例

```c
		case XDP_REDIRECT:
			stats->xdp_redirects++;
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err) {
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
```

深入`xdp_do_redirect`查看

```c
/* net/core/filter.c */

int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp,
		    struct bpf_prog *xdp_prog)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	enum bpf_map_type map_type = ri->map_type;

	/* XDP_REDIRECT is not fully supported yet for xdp frags since
	 * not all XDP capable drivers can map non-linear xdp_frame in
	 * ndo_xdp_xmit.
	 */
	if (unlikely(xdp_buff_has_frags(xdp) &&
		     map_type != BPF_MAP_TYPE_CPUMAP))
		return -EOPNOTSUPP;

	if (map_type == BPF_MAP_TYPE_XSKMAP)
		return __xdp_do_redirect_xsk(ri, dev, xdp, xdp_prog);

	return __xdp_do_redirect_frame(ri, dev, xdp_convert_buff_to_frame(xdp),
				       xdp_prog);
}
EXPORT_SYMBOL_GPL(xdp_do_redirect);
```

如果是转发到 device ，则进入到`__xdp_do_redirect_frame`

```c
/* net/core/filter.c */

static __always_inline int __xdp_do_redirect_frame(struct bpf_redirect_info *ri,
						   struct net_device *dev,
						   struct xdp_frame *xdpf,
						   struct bpf_prog *xdp_prog)
{
	enum bpf_map_type map_type = ri->map_type;
	void *fwd = ri->tgt_value;
	u32 map_id = ri->map_id;
	struct bpf_map *map;
	int err;

	ri->map_id = 0; /* Valid map id idr range: [1,INT_MAX[ */
	ri->map_type = BPF_MAP_TYPE_UNSPEC;

	if (unlikely(!xdpf)) {
		err = -EOVERFLOW;
		goto err;
	}

	switch (map_type) {
	case BPF_MAP_TYPE_DEVMAP:
		fallthrough;
	case BPF_MAP_TYPE_DEVMAP_HASH:
		map = READ_ONCE(ri->map);
		if (unlikely(map)) {
			WRITE_ONCE(ri->map, NULL);
			err = dev_map_enqueue_multi(xdpf, dev, map,
						    ri->flags & BPF_F_EXCLUDE_INGRESS);
		} else {
			err = dev_map_enqueue(fwd, xdpf, dev);
		}
		break;
	case BPF_MAP_TYPE_CPUMAP:
		err = cpu_map_enqueue(fwd, xdpf, dev);
		break;
	case BPF_MAP_TYPE_UNSPEC:
		if (map_id == INT_MAX) {
			fwd = dev_get_by_index_rcu(dev_net(dev), ri->tgt_index);
			if (unlikely(!fwd)) {
				err = -EINVAL;
				break;
			}
			err = dev_xdp_enqueue(fwd, xdpf, dev);
			break;
		}
		fallthrough;
	default:
		err = -EBADRQC;
	}

	if (unlikely(err))
		goto err;

	_trace_xdp_redirect_map(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index);
	return 0;
err:
	_trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index, err);
	return err;
}
```

以 devmap 为例，通过`dev_map_enqueue`入队

```c
/* kernel/bpf/devmap.c */

int dev_map_enqueue(struct bpf_dtab_netdev *dst, struct xdp_frame *xdpf,
		    struct net_device *dev_rx)
{
	struct net_device *dev = dst->dev;

	return __xdp_enqueue(dev, xdpf, dev_rx, dst->xdp_prog);
}

static inline int __xdp_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
				struct net_device *dev_rx,
				struct bpf_prog *xdp_prog)
{
	int err;

	if (!dev->netdev_ops->ndo_xdp_xmit)
		return -EOPNOTSUPP;

	err = xdp_ok_fwd_dev(dev, xdpf->len);
	if (unlikely(err))
		return err;

	bq_enqueue(dev, xdpf, dev_rx, xdp_prog);
	return 0;
}

static void bq_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
		       struct net_device *dev_rx, struct bpf_prog *xdp_prog)
{
	struct list_head *flush_list = this_cpu_ptr(&dev_flush_list);
	struct xdp_dev_bulk_queue *bq = this_cpu_ptr(dev->xdp_bulkq);

	if (unlikely(bq->count == DEV_MAP_BULK_SIZE))
		bq_xmit_all(bq, 0);

	/* Ingress dev_rx will be the same for all xdp_frame's in
	 * bulk_queue, because bq stored per-CPU and must be flushed
	 * from net_device drivers NAPI func end.
	 *
	 * Do the same with xdp_prog and flush_list since these fields
	 * are only ever modified together.
	 */
	if (!bq->dev_rx) {
		bq->dev_rx = dev_rx;
		bq->xdp_prog = xdp_prog;
		list_add(&bq->flush_node, flush_list);
	}

	bq->q[bq->count++] = xdpf;
}

```

在`bq_enqueue`，通过`list_add`将`flush_node`放到`flush_list`链表中，再通过`bq->q[bq->count++] = xdpf`将 XDP 帧挂到了队列中。

回过头去看`receive_mergeable`函数中的`case XDP_REDIRECT`，最后将`xdp_xmit`设置为了`VIRTIO_XDP_REDIR`

```c
*xdp_xmit |= VIRTIO_XDP_REDIR;
```

再回头去看`virtnet_poll`函数

```c
if (xdp_xmit & VIRTIO_XDP_REDIR)
		xdp_do_flush();
```

如果`xdp_xmit`中包含`VIRTIO_XDP_REDIR`位，就会执行`xdp_do_flush`

```c
void xdp_do_flush(void)
{
	__dev_flush();
	__cpu_map_flush();
	__xsk_map_flush();
}
EXPORT_SYMBOL_GPL(xdp_do_flush);
```

以`__dev_flush`为例进入查看

```c
/* __dev_flush is called from xdp_do_flush() which _must_ be signalled from the
 * driver before returning from its napi->poll() routine. See the comment above
 * xdp_do_flush() in filter.c.
 */
void __dev_flush(void)
{
	struct list_head *flush_list = this_cpu_ptr(&dev_flush_list);
	struct xdp_dev_bulk_queue *bq, *tmp;

	list_for_each_entry_safe(bq, tmp, flush_list, flush_node) {
		bq_xmit_all(bq, XDP_XMIT_FLUSH);
		bq->dev_rx = NULL;
		bq->xdp_prog = NULL;
		__list_del_clearprev(&bq->flush_node);
	}
}
```

可以看出，通过`list_for_each_entry_safe`宏遍历了`flush_list`链表，并使用`bq_xmit_all`进行了传输动作