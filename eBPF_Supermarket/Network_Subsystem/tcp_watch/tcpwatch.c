#include "tcpwatch.h"
#include "tcpwatch.skel.h"
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile bool exiting = false;

static int sport = 0, dport = 0; // for filter

static const char argp_program_doc[] = "Watch tcp/ip in network subsystem \n";

static const struct argp_option opts[] = {
    {"sport", 's', "SPORT", 0, "trace this source port only"},
    {"dport", 'd', "DPORT", 0, "trace this destination port only"},
    {}};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    char *end;
    switch (key) {
    case 's':
        sport = strtoul(arg, &end, 10);
        break;
    case 'd':
        dport = strtoul(arg, &end, 10);
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

static void sig_handler(int signo) { exiting = true; }

static const char *state_to_str(char state) {
    switch (state) {
    case TCP_ESTABLISHED:
        return "ESTABLISHED";
    default:
        return "UNKONWN";
    }
}

static void bytes_to_str(char *str, unsigned long long num) {
    if (num > 1e9) {
        sprintf(str, "%.8lfG", (double)num / 1e9);
    } else if (num > 1e6) {
        sprintf(str, "%.6lfM", (double)num / 1e6);
    } else if (num > 1e3) {
        sprintf(str, "%.3lfK", (double)num / 1e3);
    } else {
        sprintf(str, "%llu", num);
    }
}

static int print_conns(struct tcpwatch_bpf *skel) {

    FILE *file = fopen("./data/connects.log", "w");
    if (file == NULL) {
        fprintf(stderr, "Failed to open connects.log: (%s)\n", strerror(errno));
        return 0;
    }

    int map_fd = bpf_map__fd(skel->maps.conns_info);
    struct sock *sk = NULL;

    while (bpf_map_get_next_key(map_fd, &sk, &sk) == 0) {
        fprintf(stdout, "next_sk: (%p)\n", sk);
        struct conn_t d = {};
        int err = bpf_map_lookup_elem(map_fd, &sk, &d);
        if (err) {
            fprintf(stderr, "Failed to read value from the conns map: (%s)\n",
                    strerror(errno));
            return 0;
        }
        char s_str[INET_ADDRSTRLEN];
        char d_str[INET_ADDRSTRLEN];

        char s_str_v6[INET6_ADDRSTRLEN];
        char d_str_v6[INET6_ADDRSTRLEN];

        char s_ip_port_str[INET6_ADDRSTRLEN + 6];
        char d_ip_port_str[INET6_ADDRSTRLEN + 6];

        if (d.family == AF_INET) {
            sprintf(s_ip_port_str, "%s:%d",
                    inet_ntop(AF_INET, &d.saddr, s_str, sizeof(s_str)),
                    d.sport);
            sprintf(d_ip_port_str, "%s:%d",
                    inet_ntop(AF_INET, &d.daddr, d_str, sizeof(d_str)),
                    d.dport);
        } else { // AF_INET6
            sprintf(
                s_ip_port_str, "%s:%d",
                inet_ntop(AF_INET6, &d.saddr_v6, s_str_v6, sizeof(s_str_v6)),
                d.sport);
            sprintf(
                d_ip_port_str, "%s:%d",
                inet_ntop(AF_INET6, &d.daddr_v6, d_str_v6, sizeof(d_str_v6)),
                d.dport);
        }
        char received_bytes[11], acked_bytes[11];
        bytes_to_str(received_bytes, d.bytes_received);
        bytes_to_str(acked_bytes, d.bytes_acked);

        fprintf(file,
                "connection{sock=\"%p\",src=\"%s\",dst=\"%s\",rx=\"%s\","
                "tx=\"%s\",srtt=\"%u\",duration=\"%llu\"} 0\n",
                d.sock, s_ip_port_str, d_ip_port_str, received_bytes,
                acked_bytes, d.srtt, d.duration);
    }
    fclose(file);
    return 0;
}

int main(int argc, char **argv) {
    struct tcpwatch_bpf *skel;
    int err;
    /* Parse command line arguments */
    if (argc > 1) {
        err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
        if (err)
            return err;
    }

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open load and verify BPF application */
    skel = tcpwatch_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Parameterize BPF code */
    skel->rodata->filter_dport = dport;
    skel->rodata->filter_sport = sport;
    fprintf(stdout, "Filter source port: %d\n", skel->rodata->filter_sport);
    fprintf(stdout, "Filter destination port: %d\n",
            skel->rodata->filter_dport);

    err = tcpwatch_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = tcpwatch_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Process events */
    while (!exiting) {
        print_conns(skel);
        sleep(1);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    tcpwatch_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}