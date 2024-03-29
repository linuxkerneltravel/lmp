#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>

#include "delay_analysis.h"
#include "delay_analysis.skel.h"

static volatile bool exiting = false;

int count = 0;
int count_i = 0;
bool verbose = false;
int _is_send = 0; 	/** default is receive path */
int _is_ipv6 = 0; 	/** default is ipv4 */

int sport,dport,sampling;

const char argp_program_doc[] = "Trace time delay in network subsystem \n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "sport", 's', "SPORT", 0, "trace this source port only" },
    { "dport", 'd', "DPORT", 0, "trace this destination port only" },
    { "sample", 'S', "SAMPLING", 0, "Trace sampling" },
	{ "count", 'c', "COUNT", 0, "count of outputs"},
    { "Out", 'O', "OUT", 0, "in/out(1/0),default is in"},
	{"ipv6", '6', "IPV6", 0, "0:ipv4, 1:ipv6, ipv4 is default"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{   
    char *end;
    switch(key){
        case 'v':
            verbose = true;
            break;
        case 's':
            sport = strtoul(arg,&end,10);
            break;
        case 'd':
            dport = strtoul(arg,&end,10);
            break;
        case 'S':
            sampling = strtoul(arg,&end,10);
            break;
		case 'c':
			count = strtoul(arg,&end,10);
			break;
		case 'O':
			_is_send = strtoul(arg,&end,10);
			break;
		case '6':
			_is_ipv6 = strtoul(arg, &end, 10);
			break; 
        default:
		    return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static void sig_handler(int sig)
{
	exiting = true;
}



static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct data_t *d = data;
    char s_str[INET_ADDRSTRLEN];
	char d_str[INET_ADDRSTRLEN];

	char s_str_v6[INET6_ADDRSTRLEN];
	char d_str_v6[INET6_ADDRSTRLEN];
    struct in_addr src;
	struct in_addr dst;
	char s_ipv4_port_str[INET_ADDRSTRLEN+6];
	char d_ipv4_port_str[INET_ADDRSTRLEN+6];

	char s_ipv6_port_str[INET6_ADDRSTRLEN+6];
	char d_ipv6_port_str[INET6_ADDRSTRLEN+6];
	if (!_is_ipv6) {
		/** ipv4 */
		src.s_addr = d->saddr;
		dst.s_addr = d->daddr;
		sprintf(s_ipv4_port_str,"%s:%d",inet_ntop(AF_INET, &src, s_str, sizeof(s_str)),d->sport);
		sprintf(d_ipv4_port_str,"%s:%d",inet_ntop(AF_INET, &dst, d_str, sizeof(d_str)),d->dport);
		if (!_is_send) {
			// in ipv4 
			printf("%-22s %-22s %-12u %-12u %-20f %-8u %-5u %-5u %-5u %-10u\n",
				s_ipv4_port_str,
				d_ipv4_port_str,
				d->seq,
				d->ack,
				d->mac_timestamp*1e-9,
				(unsigned int)(d->total_time/1000),
				(unsigned int)(d->mac_time/1000),
				(unsigned int)(d->ip_time/1000),
				(unsigned int)(d->tcp_time/1000),
				(unsigned int)(d->srtt)
			);
		}
		else {
			// out ipv4
			printf("%-22s %-22s %-12u %-12u %-20f %-8u %-8u %-5u %-5u\n",
			s_ipv4_port_str,
			d_ipv4_port_str,
			d->seq,
			d->ack,
			d->qdisc_timestamp*1e-9,
			(unsigned int)(d->total_time/1000),     // ms
			(unsigned int)(d->qdisc_time/1000),
			(unsigned int)(d->ip_time/1000),
			(unsigned int)(d->tcp_time/1000)
			);
		}
	}
	/** ipv6 */
	else {
		src.s_addr = d->saddr_v6;
		dst.s_addr = d->daddr_v6;
		sprintf(s_ipv6_port_str,"%s:%d",inet_ntop(AF_INET6, &src, s_str_v6, sizeof(s_str_v6)),d->sport);
    	sprintf(d_ipv6_port_str,"%s:%d",inet_ntop(AF_INET6, &dst, d_str_v6, sizeof(d_str_v6)),d->dport);
		if (!_is_send) {
			// in ipv6 
			printf("%-42s %-42s %-12u %-12u %-20f %-8u %-5u %-5u %-5u\n",
			s_ipv6_port_str,
			d_ipv6_port_str,
			d->seq,
			d->ack,
			d->mac_timestamp*1e-9,
			(unsigned int)(d->total_time/1000),
			(unsigned int)(d->mac_time/1000),
			(unsigned int)(d->ip_time/1000),
			(unsigned int)(d->tcp_time/1000)
			);
		}
		else {
			// out ipv6
			 printf("%-42s %-42s %-12u %-12u %-20f %-8u %-8u %-5u %-5u\n",
			s_ipv6_port_str,
			d_ipv6_port_str,
			d->seq,
			d->ack,
			d->qdisc_timestamp*1e-9,
			(unsigned int)(d->total_time/1000),     // ms
			(unsigned int)(d->qdisc_time/1000),
			(unsigned int)(d->ip_time/1000),
			(unsigned int)(d->tcp_time/1000)
			);
		}
	}
	count_i++;
    return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct delay_analysis_bpf *skel;
	int err = 0;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = delay_analysis_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    /* Parameterize BPF code */
    skel->rodata->filter_dport = dport;
    skel->rodata->filter_sport = sport;
    skel->rodata->sampling = sampling;
	skel->rodata->_is_ipv6 = _is_ipv6;
	skel->rodata->_is_send = _is_send;

    /* Load & verify BPF programs */
	err = delay_analysis_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    /* Attach tracepoints */
	err = delay_analysis_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	if (_is_ipv6) {
		if(_is_send){
			printf("%-42s %-42s %-12s %-12s %-20s %-8s %-5s %-5s %-5s\n" ,
			"SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "TIME", "TOTAL", "QDisc", "IP", "TCP");
		}
		else{
			printf("%-42s %-42s %-12s %-12s %-20s %-8s %-5s %-5s %-5s\n" ,
			"SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "TIME", "TOTAL", "MAC", "IP", "TCP");
		}
	}
	else {
		if(_is_send){
			printf("%-22s %-22s %-12s %-12s %-20s %-8s %-5s %-5s %-5s\n" ,
			"SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "TIME", "TOTAL", "QDisc", "IP", "TCP");
		}
		else{
			printf("%-22s %-22s %-12s %-12s %-20s %-8s %-5s %-5s %-5s %-10s\n" ,
			"SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "TIME", "TOTAL", "MAC", "IP", "TCP","SRTT");
		}

	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		if(count != 0 && count_i>=count)
			break;
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	delay_analysis_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}