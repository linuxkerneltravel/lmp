#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "schedule_delay.skel.h"  // 内核态 skeleton
#include "cpu.h"                  // 定义 sum_schedule, proc_schedule, proc_id, proc_history
#include "mem_monitor.skel.h"     // mem_monitor skeleton
#include "mem.h"
#include "io_monitor.skel.h"      // io_monitor skeleton
#include "io.h"
#include "trace_helpers.h"
#include <arpa/inet.h>
#include <pthread.h>

#undef TASK_COMM_LEN
#define event tcpstates_event
#include "tcpstates.h"
#undef event
#undef TASK_COMM_LEN
#define event tcplife_event
#include "tcplife.h"
#undef event
#undef TASK_COMM_LEN
#define event tcpconn_event
#include "tcpconnlat.h"
#undef event
#include "tcpstates.skel.h"
#include "tcplife.skel.h"
#include "tcpconnect.skel.h"

#define SEEN_MAX_ENTRIES 1024
#define SOCKET_PATH "/tmp/bpf_trigger.sock"

#define OUTPUT_ROWS_LIMIT 20
#define warn(...) fprintf(stderr, __VA_ARGS__)

struct output_entry {
    int pid;
    char comm[16];
    long long delay;
};

struct output_entry seen_entries[SEEN_MAX_ENTRIES];
int seen_count = 0;

struct schedule_delay_bpf *skel_sched;
struct mem_monitor_bpf *skel_mem;
struct io_monitor_bpf *skel_io;

struct tcpstates_bpf *skel_tcpstates;
struct tcplife_bpf *skel_tcplife;
struct tcpconnect_bpf *skel_tcpconn;

struct perf_buffer *pb_tcpstates;
struct perf_buffer *pb_tcplife;
struct perf_buffer *pb_tcpconn;

pthread_t th_tcpstates;
pthread_t th_tcplife;
pthread_t th_tcpconn;

volatile int net_print_tcpstates = 0;
volatile int net_print_tcplife = 0;
volatile int net_print_connlat = 0;
volatile sig_atomic_t exiting_net = 0;

// 分块输出：为三类网络事件增加缓冲与互斥
#include <pthread.h>
static pthread_mutex_t net_buf_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct lines_buf {
    char **lines;
    size_t count;
    size_t capacity;
} lines_buf_t;

static void lines_buf_clear(lines_buf_t *b) {
    if (!b) return;
    for (size_t i = 0; i < b->count; i++) {
        free(b->lines[i]);
    }
    free(b->lines);
    b->lines = NULL;
    b->count = 0;
    b->capacity = 0;
}

static void lines_buf_append(lines_buf_t *b, const char *line) {
    if (!b || !line) return;
    if (b->count == b->capacity) {
        size_t newcap = b->capacity ? (b->capacity * 2) : 128;
        char **newlines = (char **)realloc(b->lines, newcap * sizeof(char *));
        if (!newlines) return;
        b->lines = newlines;
        b->capacity = newcap;
    }
    size_t len = strlen(line);
    char *copy = (char *)malloc(len + 1);
    if (!copy) return;
    memcpy(copy, line, len + 1);
    b->lines[b->count++] = copy;
}

static lines_buf_t buf_tcpstates = {0};
static lines_buf_t buf_tcplife = {0};
static lines_buf_t buf_tcpconn = {0};

static void print_and_clear_grouped_output(void) {
    // 若没有任何内容，直接返回
    if (buf_tcpstates.count == 0 && buf_tcplife.count == 0 && buf_tcpconn.count == 0) {
        return;
    }
    printf(">>> NET 本次异常分块输出 <<<\n");

    // TCPSTATES
    printf("[TCPSTATES] %-8s %-16s %-7s %-10s %-15s %-5s %-15s %-5s %-11s -> %-11s %8s\n",
           "TIME(s)", "SKADDR", "PID", "COMM", "LADDR", "LPORT",
           "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");
    for (size_t i = 0; i < buf_tcpstates.count; i++) {
        puts(buf_tcpstates.lines[i]);
    }

    // TCPLIFE
    printf("[TCPLIFE] %-8s %-7s %-16s %-15s %-5s %-15s %-5s %8s %8s %8s\n",
           "TIME(s)", "PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT",
           "TX_KB", "RX_KB", "MS");
    for (size_t i = 0; i < buf_tcplife.count; i++) {
        puts(buf_tcplife.lines[i]);
    }

    // TCPCONNECT
    printf("[TCPCONNECT] %-8s %-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n",
           "TIME(s)", "PID", "COMM", "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)");
    for (size_t i = 0; i < buf_tcpconn.count; i++) {
        puts(buf_tcpconn.lines[i]);
    }

    lines_buf_clear(&buf_tcpstates);
    lines_buf_clear(&buf_tcplife);
    lines_buf_clear(&buf_tcpconn);
}

/* ---------------- schedule 部分 ---------------- */
void schedule_print() {
    int key = 0;
    time_t now = time(NULL);
    struct tm *localTime = localtime(&now);

    printf("%-8s %-15s %-15s %-16s %-15s %-16s\n",
           "TIME", "AVG_DELAY(us)", "MAX_DELAY(us)", "MAX_PROC", "MIN_DELAY(us)", "MIN_PROC");

    struct sum_schedule info;
    int fd_sum = bpf_map__fd(skel_sched->maps.sys_schedule);
    if (bpf_map_lookup_elem(fd_sum, &key, &info) < 0) {
        perror("failed to lookup sum_schedule");
        return;
    }

    unsigned long long avg_delay = info.sum_count ? (info.sum_delay / info.sum_count) : 0;

    printf("%02d:%02d:%02d %-15llu %-15llu %-16s %-15llu %-16s\n",
           localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
           avg_delay / 1000, info.max_delay / 1000, info.proc_name_max,
           info.min_delay / 1000, info.proc_name_min);
}

/* ---------------- mem_monitor 部分 ---------------- */
int str_loadavg(char *buf, size_t buf_len) {
    int n, err = 0;
    char avg[64] = {0};
    FILE *f;

    if (!buf || buf_len == 0)
        return -EINVAL;

    f = fopen("/proc/loadavg", "r");
    if (!f)
        return -errno;

    n = fread(avg, 1, sizeof(avg) - 1, f);
    if (!n) {
        err = -errno;
        goto cleanup;
    }

    n = snprintf(buf, buf_len, "loadavg: %s", avg);

    if (n >= buf_len)
        err = -ERANGE;

cleanup:
    fclose(f);
    return err ?: n;
}

int str_timestamp(const char *format, char *buf, size_t buf_len) {
    time_t t;
    struct tm *tm;

    if (!format || !buf || buf_len == 0)
        return -EINVAL;

    time(&t);
    tm = localtime(&t);
    if (!tm)
        return -errno;
    return strftime(buf, buf_len, format, tm);
}

static int sort_column(const void *obj1, const void *obj2) {
    const struct slabrate_info *s1 = obj1;
    const struct slabrate_info *s2 = obj2;
    return s2->size - s1->size;
}

// 打印 slab 分配统计，增量模式
static int print_stat(struct mem_monitor_bpf *obj, bool clear_after)
{
    char loadavg[256], ts[64];
    char *key, **prev_key = NULL;
    static struct slabrate_info values[OUTPUT_ROWS_LIMIT];
    int i, err = 0, rows = 0;
    int fd = bpf_map__fd(obj->maps.slab_entries);

    // 打印时间戳和 loadavg
    err = str_loadavg(loadavg, sizeof(loadavg)) <= 0;
    err = err ?: (str_timestamp("%H:%M:%S", ts, sizeof(ts)) <= 0);
    if (!err)
        printf("%8s %s\n", ts, loadavg);

    printf("%-32s %6s %10s\n", "CACHE", "ALLOCS", "BYTES");

    // 遍历 map
    while (1) {
        err = bpf_map_get_next_key(fd, prev_key, &key);
        if (err) {
            if (errno == ENOENT) {
                err = 0;
                break;
            }
            warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
            return err;
        }
        err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
        if (err) {
            warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
            return err;
        }
        prev_key = &key;
        if (rows >= OUTPUT_ROWS_LIMIT)
            break;
    }

    qsort(values, rows, sizeof(struct slabrate_info), sort_column);
    for (i = 0; i < rows; i++)
        printf("%-32s %6lld %10lld\n",
               values[i].name, values[i].count, values[i].size);

    printf("\n");

    // 增量模式：打印后清空 map
    if (clear_after) {
        prev_key = NULL;
        while (1) {
            err = bpf_map_get_next_key(fd, prev_key, &key);
            if (err) {
                if (errno == ENOENT) {
                    err = 0;
                    break;
                }
                warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
                return err;
            }
            err = bpf_map_delete_elem(fd, &key);
            if (err) {
                warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
                return err;
            }
            prev_key = &key;
        }
    }

    return err;
}

/* ---------------- io_monitor 部分 ---------------- */
static int io_sort_desc(const void *obj1, const void *obj2) {
    const struct io_stat *a = obj1;
    const struct io_stat *b = obj2;
    __u64 ta = a->read_bytes + a->write_bytes;
    __u64 tb = b->read_bytes + b->write_bytes;
    if (tb > ta) return 1;
    if (tb < ta) return -1;
    return 0;
}

static int print_io_stat(struct io_monitor_bpf *obj, bool clear_after)
{
    char loadavg[256], ts[64];
    __u32 cur_key = 0, next_key;
    bool have_prev = false;
    struct io_row { __u32 pid; struct io_stat val; } rows_buf[OUTPUT_ROWS_LIMIT];
    int i, err = 0, rows = 0;
    int fd = bpf_map__fd(obj->maps.io_stats);

    err = str_loadavg(loadavg, sizeof(loadavg)) <= 0;
    err = err ?: (str_timestamp("%H:%M:%S", ts, sizeof(ts)) <= 0);
    if (!err)
        printf("%8s %s\n", ts, loadavg);

    printf("%-8s %-16s %-12s %-12s %-10s %-10s\n",
           "PID", "COMM", "READ_BYTES", "WRITE_BYTES", "R_CALLS", "W_CALLS");

    // 遍历 map（标量键的安全遍历模式）
    while (bpf_map_get_next_key(fd, have_prev ? &cur_key : NULL, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &rows_buf[rows].val) != 0) {
            warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
            return -1;
        }
        rows_buf[rows].pid = next_key;
        rows++;
        cur_key = next_key;
        have_prev = true;
        if (rows >= OUTPUT_ROWS_LIMIT)
            break;
    }

    // 简单选择排序，按总字节降序，保证 pid 与值一起移动
    for (i = 0; i < rows; i++) {
        int j, best = i;
        for (j = i + 1; j < rows; j++) {
            if (io_sort_desc(&rows_buf[j].val, &rows_buf[best].val) > 0)
                best = j;
        }
        if (best != i) {
            struct io_row tmp = rows_buf[i];
            rows_buf[i] = rows_buf[best];
            rows_buf[best] = tmp;
        }
    }
    for (i = 0; i < rows; i++) {
        printf("%-8u %-16s %-12llu %-12llu %-10llu %-10llu\n",
               rows_buf[i].pid, rows_buf[i].val.comm,
               (unsigned long long)rows_buf[i].val.read_bytes,
               (unsigned long long)rows_buf[i].val.write_bytes,
               (unsigned long long)rows_buf[i].val.read_calls,
               (unsigned long long)rows_buf[i].val.write_calls);
    }
    printf("\n");

    if (clear_after) {
        have_prev = false;
        while (bpf_map_get_next_key(fd, have_prev ? &cur_key : NULL, &next_key) == 0) {
            if (bpf_map_delete_elem(fd, &next_key) != 0) {
                warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
                return -1;
            }
            cur_key = next_key;
            have_prev = true;
        }
    }
    return 0;
}

/* ---------------- socket 监听 ---------------- */
void listen_socket() {
    int sockfd;
    struct sockaddr_un addr;
    char buf[128];

    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket error");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCKET_PATH);
    unlink(SOCKET_PATH);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind error");
        exit(1);
    }

    if (chmod(SOCKET_PATH, 0666) < 0) {
        perror("chmod error");
        exit(1);
    }

    printf("等待 Python 异常检测通知 (Socket: %s)...\n", SOCKET_PATH);

    while (1) {
        int n = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            printf("收到异常维度: %s\n", buf);

            if (strstr(buf, "CPU")) {
                printf(">>> CPU 异常触发，打印调度延迟 <<<\n");
                schedule_print();
            }
            if (strstr(buf, "MEM")) {
                printf(">>> MEM 异常触发，打印 slab 分配详情 <<<\n");
                print_stat(skel_mem, true); // 增量打印
            }
            if (strstr(buf, "IO")) {
                printf(">>> IO 异常触发，打印进程 I/O 统计 <<<\n");
                print_io_stat(skel_io, true);
            }
            if (strstr(buf, "NET_STATE")) {
                printf(">>> NET tcpstates 开启打印 <<<\n");
                pthread_mutex_lock(&net_buf_lock);
                lines_buf_clear(&buf_tcpstates);
                lines_buf_clear(&buf_tcplife);
                lines_buf_clear(&buf_tcpconn);
                pthread_mutex_unlock(&net_buf_lock);
                net_print_tcpstates = 1;
            }
            if (strstr(buf, "NET_LIFE")) {
                printf(">>> NET tcplife 开启打印 <<<\n");
                pthread_mutex_lock(&net_buf_lock);
                lines_buf_clear(&buf_tcpstates);
                lines_buf_clear(&buf_tcplife);
                lines_buf_clear(&buf_tcpconn);
                pthread_mutex_unlock(&net_buf_lock);
                net_print_tcplife = 1;
            }
            if (strstr(buf, "NET_CONN")) {
                printf(">>> NET tcpconnect 开启打印 <<<\n");
                pthread_mutex_lock(&net_buf_lock);
                lines_buf_clear(&buf_tcpstates);
                lines_buf_clear(&buf_tcplife);
                lines_buf_clear(&buf_tcpconn);
                pthread_mutex_unlock(&net_buf_lock);
                net_print_connlat = 1;
            }
            if (strstr(buf, "NET") && !strstr(buf, "NET_STATE") && !strstr(buf, "NET_LIFE") && !strstr(buf, "NET_CONN") && !strstr(buf, "NET_OFF")) {
                printf(">>> NET 默认开启打印 (tcpstates + tcplife + tcpconnect) <<<\n");
                pthread_mutex_lock(&net_buf_lock);
                lines_buf_clear(&buf_tcpstates);
                lines_buf_clear(&buf_tcplife);
                lines_buf_clear(&buf_tcpconn);
                pthread_mutex_unlock(&net_buf_lock);
                net_print_tcpstates = 1;
                net_print_tcplife = 1;
                net_print_connlat = 1;
            }
            if (strstr(buf, "NET_OFF")) {
                printf(">>> NET 关闭打印 <<<\n");
                net_print_tcpstates = 0;
                net_print_tcplife = 0;
                net_print_connlat = 0;
                pthread_mutex_lock(&net_buf_lock);
                print_and_clear_grouped_output();
                pthread_mutex_unlock(&net_buf_lock);
            }
        }
    }

    close(sockfd);
}

static void *poll_tcpstates(void *arg) {
    while (!exiting_net)
        perf_buffer__poll(pb_tcpstates, 100);
    return NULL;
}

static void *poll_tcplife(void *arg) {
    while (!exiting_net)
        perf_buffer__poll(pb_tcplife, 100);
    return NULL;
}

static void *poll_tcpconn(void *arg) {
    while (!exiting_net)
        perf_buffer__poll(pb_tcpconn, 100);
    return NULL;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

/* ---------------- net monitor 部分 ---------------- */
static const char *tcp_state_names[] = {
    [1] = "ESTABLISHED",
    [2] = "SYN_SENT",
    [3] = "SYN_RECV",
    [4] = "FIN_WAIT1",
    [5] = "FIN_WAIT2",
    [6] = "TIME_WAIT",
    [7] = "CLOSE",
    [8] = "CLOSE_WAIT",
    [9] = "LAST_ACK",
    [10] = "LISTEN",
    [11] = "CLOSING",
    [12] = "NEW_SYN_RECV",
    [13] = "UNKNOWN",
};

static void handle_tcpstates_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    if (!net_print_tcpstates) return;
    char ts[32], saddr[39], daddr[39];
    struct tcpstates_event e;
    if (data_sz < sizeof(e)) return;
    memcpy(&e, data, sizeof(e));
    str_timestamp("%H:%M:%S", ts, sizeof(ts));
    inet_ntop(e.family, &e.saddr, saddr, sizeof(saddr));
    inet_ntop(e.family, &e.daddr, daddr, sizeof(daddr));
    char line[512];
    snprintf(line, sizeof(line),
             "%-8s %-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %8.3f",
             ts, e.skaddr, e.pid, e.task, saddr, e.sport, daddr, e.dport,
             tcp_state_names[e.oldstate], tcp_state_names[e.newstate], (double)e.delta_us / 1000);
    pthread_mutex_lock(&net_buf_lock);
    lines_buf_append(&buf_tcpstates, line);
    pthread_mutex_unlock(&net_buf_lock);
}

static void handle_tcplife_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    if (!net_print_tcplife) return;
    char ts[32], saddr[48], daddr[48];
    struct tcplife_event e;
    if (data_sz < sizeof(e)) return;
    memcpy(&e, data, sizeof(e));
    str_timestamp("%H:%M:%S", ts, sizeof(ts));
    inet_ntop(e.family, &e.saddr, saddr, sizeof(saddr));
    inet_ntop(e.family, &e.daddr, daddr, sizeof(daddr));
    char line[512];
    snprintf(line, sizeof(line),
             "%-8s %-7d %-16s %-15s %-5d %-15s %-5d %8.2f %8.2f %8.2f",
             ts, e.pid, e.comm, saddr, e.sport, daddr, e.dport,
             (double)e.tx_b / 1024, (double)e.rx_b / 1024, (double)e.span_us / 1000);
    pthread_mutex_lock(&net_buf_lock);
    lines_buf_append(&buf_tcplife, line);
    pthread_mutex_unlock(&net_buf_lock);
}

static void handle_tcpconn_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    if (!net_print_connlat) return;
    const struct tcpconn_event *e = data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    union { struct in_addr x4; struct in6_addr x6; } s, d;
    if (e->af == AF_INET) {
        s.x4.s_addr = e->saddr_v4;
        d.x4.s_addr = e->daddr_v4;
    } else if (e->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "broken event: event->af=%u\n", e->af);
        return;
    }
    char ts[32];
    str_timestamp("%H:%M:%S", ts, sizeof(ts));
    char line[512];
    snprintf(line, sizeof(line),
             "%-8s %-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %8.2f",
             ts,
             e->tgid, e->comm,
             e->af == AF_INET ? 4 : 6,
             inet_ntop(e->af, &s, src, sizeof(src)),
             e->lport,
             inet_ntop(e->af, &d, dst, sizeof(dst)),
             ntohs(e->dport),
             e->delta_us / 1000.0);
    pthread_mutex_lock(&net_buf_lock);
    lines_buf_append(&buf_tcpconn, line);
    pthread_mutex_unlock(&net_buf_lock);
}

static int init_net_modules(void)
{
    pb_tcpstates = NULL; pb_tcplife = NULL; pb_tcpconn = NULL;

    skel_tcpstates = tcpstates_bpf__open_and_load();
    if (!skel_tcpstates) return -1;
    if (tcpstates_bpf__attach(skel_tcpstates) != 0) return -1;
    pb_tcpstates = perf_buffer__new(bpf_map__fd(skel_tcpstates->maps.events), 16,
                                     handle_tcpstates_event, handle_lost_events, NULL, NULL);
    if (!pb_tcpstates) return -1;
    pthread_create(&th_tcpstates, NULL, poll_tcpstates, NULL);

    skel_tcplife = tcplife_bpf__open_and_load();
    if (!skel_tcplife) return -1;
    if (tcplife_bpf__attach(skel_tcplife) != 0) return -1;
    pb_tcplife = perf_buffer__new(bpf_map__fd(skel_tcplife->maps.events), 16,
                                     handle_tcplife_event, handle_lost_events, NULL, NULL);
    if (!pb_tcplife) return -1;
    pthread_create(&th_tcplife, NULL, poll_tcplife, NULL);

    skel_tcpconn = tcpconnect_bpf__open_and_load();
    if (!skel_tcpconn) return -1;
    if (tcpconnect_bpf__attach(skel_tcpconn) != 0) return -1;
    pb_tcpconn = perf_buffer__new(bpf_map__fd(skel_tcpconn->maps.events), 16,
                                     handle_tcpconn_event, handle_lost_events, NULL, NULL);
    if (!pb_tcpconn) return -1;
    pthread_create(&th_tcpconn, NULL, poll_tcpconn, NULL);

    printf("tcpstates/tcplife/tcpconnect eBPF skeletons loaded and attached!\n");
    return 0;
}

static void destroy_net_modules(void)
{
    exiting_net = 1;
    if (th_tcpstates) pthread_join(th_tcpstates, NULL);
    if (th_tcplife) pthread_join(th_tcplife, NULL);
    if (th_tcpconn) pthread_join(th_tcpconn, NULL);

    perf_buffer__free(pb_tcpstates);
    perf_buffer__free(pb_tcplife);
    perf_buffer__free(pb_tcpconn);

    if (skel_tcpstates) tcpstates_bpf__destroy(skel_tcpstates);
    if (skel_tcplife) tcplife_bpf__destroy(skel_tcplife);
    if (skel_tcpconn) tcpconnect_bpf__destroy(skel_tcpconn);
}

/* ---------------- main ---------------- */
int main(int argc, char **argv) {
    /* 加载 schedule_delay skeleton */
    skel_sched = schedule_delay_bpf__open_and_load();
    if (!skel_sched) {
        fprintf(stderr, "Failed to open and load schedule_delay skeleton\n");
        return 1;
    }
    if (schedule_delay_bpf__attach(skel_sched) != 0) {
        fprintf(stderr, "Failed to attach schedule_delay skeleton\n");
        schedule_delay_bpf__destroy(skel_sched);
        return 1;
    }
    printf("schedule_delay eBPF skeleton loaded and attached!\n");

    /* 加载 mem_monitor skeleton (只 load 一次) */
    skel_mem = mem_monitor_bpf__open_and_load();
    if (!skel_mem) {
        fprintf(stderr, "Failed to open and load mem_monitor skeleton\n");
        return 1;
    }
    if (mem_monitor_bpf__attach(skel_mem) != 0) {
        fprintf(stderr, "Failed to attach mem_monitor skeleton\n");
        mem_monitor_bpf__destroy(skel_mem);
        return 1;
    }
    printf("mem_monitor eBPF skeleton loaded and attached!\n");

    /* 加载 io_monitor skeleton */
    skel_io = io_monitor_bpf__open_and_load();
    if (!skel_io) {
        fprintf(stderr, "Failed to open and load io_monitor skeleton\n");
        return 1;
    }
    if (io_monitor_bpf__attach(skel_io) != 0) {
        fprintf(stderr, "Failed to attach io_monitor skeleton\n");
        io_monitor_bpf__destroy(skel_io);
        return 1;
    }
    printf("io_monitor eBPF skeleton loaded and attached!\n");

    /* 加载网络相关 skeleton 并创建 perf buffer 线程 */
    if (init_net_modules() != 0) {
        fprintf(stderr, "Failed to init NET modules\n");
        return 1;
    }

    /* 等待 Python 异常通知 */
    listen_socket();

    /* 程序退出时销毁 skeleton */
    destroy_net_modules();
    schedule_delay_bpf__destroy(skel_sched);
    mem_monitor_bpf__destroy(skel_mem);
    io_monitor_bpf__destroy(skel_io);
    return 0;
}
