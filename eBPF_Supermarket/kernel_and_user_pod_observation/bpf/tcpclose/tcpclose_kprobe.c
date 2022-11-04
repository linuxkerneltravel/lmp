// +build ignore

// ver: 9d06ced06f63161570d5fb6376acf099225899a3
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;

    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;
    /*FILTER_LPORT*/
    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    /*FILTER_DPORT*/

    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */
    // capture birth time
    if (state < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }
    // record PID & comm on SYN_SENT
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        /*FILTER_PID*/
        struct id_t me = {.pid = pid, .tid = tid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }
    if (state != TCP_CLOSE)
        return 0;
    // calculate lifespan
    u64 *tsp, delta_ns;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_ns = bpf_ktime_get_ns() - *tsp;
    birth.delete(&sk);

    // fetch possible cached data, and filter
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0) {
		pid = mep->pid;
		tid = mep->tid;
	}
    /*FILTER_PID*/

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    u16 family = sk->__sk_common.skc_family;
    /*FILTER_FAMILY*/

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_ns = bpf_ktime_get_ns();
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.pid = pid;
		data4.tid = tid;
		data4.lport = lport;
		data4.dport = dport;
        data4.span_ns = delta_ns;
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read_kernel(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {};
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_ns = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.pid = pid;
		data6.tid = tid;
		data6.lport = lport;
		data6.dport = dport;
        data6.span_ns = delta_ns;
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read_kernel(&data6.task, sizeof(data6.task), (void *)mep->task);
        }
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    if (mep != 0)
        whoami.delete(&sk);
    return 0;
}