// +build ignore

// ver: 9d06ced06f63161570d5fb6376acf099225899a3
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->protocol != IPPROTO_TCP)
        return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;

    // sk is mostly used as a UUID, and for two tcp stats:
    struct sock *sk = (struct sock *)args->skaddr;

    // lport is either used in a filter here, or later
    u16 lport = args->sport;
	/*FILTER_LPORT*/

	// dport is either used in a filter here, or later
    u16 dport = args->dport;
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
    if (args->newstate < TCP_FIN_WAIT1) {
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
    if (args->newstate == TCP_SYN_SENT || args->newstate == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        /*FILTER_PID*/
        struct id_t me = {.pid = pid, .tid = tid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }
    if (args->newstate != TCP_CLOSE)
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

    u16 family = args->family;
    /*FILTER_FAMILY*/

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;
    if (args->family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_ns = bpf_ktime_get_ns();
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
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
        ipv4_events.perf_submit(args, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {};
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_ns = bpf_ktime_get_ns();
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
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
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }
    if (mep != 0)
        whoami.delete(&sk);
    return 0;
}