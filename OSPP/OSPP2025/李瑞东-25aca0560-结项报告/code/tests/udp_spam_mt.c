// 多线程/高频 UDP 发包器：用来触发 tc eBPF 程序（IPv4）
// 依赖：pthread
// 编译：gcc -O2 -pthread -o udp_spam_mt udp_spam_mt.c
//
// 典型用法：
//   sudo ./udp_spam_mt --dst 10.0.0.1 --dport 9999 --seconds 60 \
//                       --threads 8 --payload 512 --src 10.0.0.2
//
// 可选限速(每线程 QPS)：
//   sudo ./udp_spam_mt --dst 10.0.0.1 --dport 9999 --seconds 60 \
//                       --threads 8 --qps 10000 --payload 512 --src 10.0.0.2
//
// 说明：
// - 指定 --src 可把源 IP 绑定到 veth1(10.0.0.2)，无需 SO_BINDTODEVICE。
// - 不设 --qps 时为“全速”紧循环；设定 --qps 时近似限速（按纳秒 sleep）。
// - 支持 sendmmsg 批量发送；若系统不支持，自动退化为 sendto。
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef __linux__
#include <sys/uio.h>
#include <linux/version.h>
#endif

typedef struct {
    struct sockaddr_in dst;
    char *buf;
    int payload;
    int seconds;
    double qps_per_thread; // <=0 全速
    const char *src_ip;    // NULL 不绑定
    atomic_ullong *global_sent;
    atomic_ullong *global_err;
    atomic_bool *stop_flag;
} worker_arg_t;

static inline long long now_ns() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void busy_sleep_ns(long long ns) {
    if (ns <= 0) return;
    struct timespec req;
    req.tv_sec  = ns / 1000000000LL;
    req.tv_nsec = ns % 1000000000LL;
    nanosleep(&req, NULL);
}

static void *worker(void *arg_) {
    worker_arg_t *arg = (worker_arg_t *)arg_;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return NULL; }

    // 绑定源 IP（例如 10.0.0.2），让路由选中 veth1，无需 SO_BINDTODEVICE
    if (arg->src_ip && arg->src_ip[0]) {
        struct sockaddr_in src = {0};
        src.sin_family = AF_INET;
        src.sin_port = htons(0);
        if (inet_pton(AF_INET, arg->src_ip, &src.sin_addr) != 1) {
            fprintf(stderr, "bad --src %s\n", arg->src_ip);
            close(fd); return NULL;
        }
        if (bind(fd, (struct sockaddr*)&src, sizeof(src)) < 0) {
            perror("bind src_ip");
            close(fd); return NULL;
        }
    }

    // 提升发送缓冲
    int snd = 4<<20; setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));

    const int payload = arg->payload;
    const double qps  = arg->qps_per_thread;
    const long long interval_ns = (qps > 0) ? (long long)(1e9 / qps) : 0;

    // sendmmsg 批量：32 包/批（如果不可用，会走 sendto 分支）
    const int BATCH = 32;
#ifdef MSG_WAITFORONE
    (void)BATCH;
#endif

#if defined(SYS_sendmmsg) || defined(__NR_sendmmsg)
#define USE_SENDMMSG 1
#else
#define USE_SENDMMSG 0
#endif

#if USE_SENDMMSG
    struct mmsghdr mmsgs[BATCH];
    struct iovec iovecs[BATCH];
    struct sockaddr_in dsts[BATCH];
    for (int i = 0; i < BATCH; i++) {
        dsts[i] = arg->dst;
        iovecs[i].iov_base = arg->buf;
        iovecs[i].iov_len = payload;
        memset(&mmsgs[i], 0, sizeof(mmsgs[i]));
        mmsgs[i].msg_hdr.msg_iov = &iovecs[i];
        mmsgs[i].msg_hdr.msg_iovlen = 1;
        mmsgs[i].msg_hdr.msg_name = &dsts[i];
        mmsgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
    }
#endif

    unsigned long long sent = 0, errs = 0;
    long long end = now_ns() + (long long)arg->seconds * 1000000000LL;

    while (!atomic_load_explicit(arg->stop_flag, memory_order_relaxed)) {
        if (now_ns() >= end) break;

#if USE_SENDMMSG
        if (qps <= 0) {
            int ret = sendmmsg(fd, mmsgs, BATCH, 0);
            if (ret < 0) {
                // sendmmsg 不可用或出错时降级
                if (errno == ENOSYS) {
                    // 降级为单发
                    for (int i = 0; i < BATCH; i++) {
                        ssize_t n = sendto(fd, arg->buf, payload, 0,
                                (struct sockaddr*)&arg->dst, sizeof(arg->dst));
                        if (n < 0) errs++; else sent++;
                    }
                    continue;
                } else {
                    errs++;
                }
            } else {
                sent += ret;
            }
        } else {
            // 近似限速：每次一包 + sleep
            ssize_t n = sendto(fd, arg->buf, payload, 0,
                               (struct sockaddr*)&arg->dst, sizeof(arg->dst));
            if (n < 0) errs++; else sent++;
            busy_sleep_ns(interval_ns);
        }
#else
        if (qps <= 0) {
            // 全速
            ssize_t n = sendto(fd, arg->buf, payload, 0,
                               (struct sockaddr*)&arg->dst, sizeof(arg->dst));
            if (n < 0) errs++; else sent++;
        } else {
            // 近似限速
            ssize_t n = sendto(fd, arg->buf, payload, 0,
                               (struct sockaddr*)&arg->dst, sizeof(arg->dst));
            if (n < 0) errs++; else sent++;
            busy_sleep_ns(interval_ns);
        }
#endif
    }

    atomic_fetch_add(arg->global_sent, sent);
    atomic_fetch_add(arg->global_err, errs);
    close(fd);
    return NULL;
}

static volatile sig_atomic_t g_stop = 0;
static void on_int(int) { g_stop = 1; }

int main(int argc, char **argv) {
    const char *dst_ip = NULL;
    const char *src_ip = NULL;  // 可选
    int dst_port = 9999;
    int seconds = 30;
    int threads = 4;
    int payload = 512;
    double qps = 0.0; // 每线程 QPS，<=0 表示全速

    // 参数解析
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dst") && i+1 < argc) dst_ip = argv[++i];
        else if (!strcmp(argv[i], "--dport") && i+1 < argc) dst_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--seconds") && i+1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i+1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--payload") && i+1 < argc) payload = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--src") && i+1 < argc) src_ip = argv[++i];
        else if (!strcmp(argv[i], "--qps") && i+1 < argc) qps = atof(argv[++i]);
        else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]); return 2;
        }
    }

    if (!dst_ip) {
        fprintf(stderr, "Usage: %s --dst <ip> [--dport 9999] [--seconds 60] [--threads 8] [--payload 512] [--src <ip>] [--qps <per-thread>]\n", argv[0]);
        return 1;
    }
    if (payload < 1) payload = 1;
    if (threads < 1) threads = 1;

    // 目标地址
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "bad --dst %s\n", dst_ip); return 1;
    }

    // 共享参数
    char *buf = (char*)malloc(payload);
    if (!buf) { perror("malloc"); return 1; }
    memset(buf, 'A', payload);

    atomic_ullong g_sent = 0, g_err = 0;
    atomic_bool stop_flag = false;

    signal(SIGINT, on_int);

    pthread_t *tids = (pthread_t*)calloc(threads, sizeof(*tids));
    worker_arg_t warg = {
        .dst = dst,
        .buf = buf,
        .payload = payload,
        .seconds = seconds,
        .qps_per_thread = qps,
        .src_ip = src_ip,
        .global_sent = &g_sent,
        .global_err = &g_err,
        .stop_flag = &stop_flag
    };

    long long end = now_ns() + (long long)seconds * 1000000000LL;

    // 启动线程
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], NULL, worker, &warg) != 0) {
            perror("pthread_create"); return 1;
        }
    }

    // 主线程等待结束或 Ctrl-C
    while (!g_stop && now_ns() < end) {
        busy_sleep_ns(10000000LL); // 10ms
    }
    atomic_store(&stop_flag, true);

    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);

    unsigned long long S = atomic_load(&g_sent);
    unsigned long long E = atomic_load(&g_err);
    printf("[udp_spam_mt] threads=%d seconds=%d payload=%d dst=%s:%d src=%s qps/thread=%s\n",
           threads, seconds, payload, dst_ip, dst_port, src_ip?src_ip:"(auto)",
           (qps>0? "limited":"max"));
    printf("  sent=%llu errors=%llu\n", S, E);

    free(buf);
    free(tids);
    return 0;
}
