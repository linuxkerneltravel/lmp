// sig_storm.c
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static atomic_bool stop_flag = false;
static int workers = 1;
static int duration_sec = 0;    // 0 = 无限跑
static long sleep_ns = 0;       // 每轮小睡，降低 IPI/调度开销

// ========== 工具函数 ==========
static inline pid_t gettid_inline(void) {
#ifdef SYS_gettid
  return (pid_t)syscall(SYS_gettid);
#else
  return (pid_t)getpid(); // 退化
#endif
}

static inline long tgkill_sys(pid_t tgid, pid_t tid, int sig) {
#ifdef SYS_tgkill
  return syscall(SYS_tgkill, tgid, tid, sig);
#else
  errno = ENOSYS;
  return -1;
#endif
}

static void sleep_until_deadline_s(int sec) {
  if (sec <= 0) return;
  struct timespec now, dl;
  clock_gettime(CLOCK_MONOTONIC, &now);
  dl.tv_sec  = now.tv_sec + sec;
  dl.tv_nsec = now.tv_nsec;
  // 绝对时间休眠，被信号打断会继续等到绝对时刻
  while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &dl, NULL) == EINTR) {}
}

// ========== 信号处理 ==========
static void sigusr1_handler(int signo) {
  (void)signo; // 吞掉信号，不做任何事，避免退出
}

static void sigint_handler(int signo) {
  (void)signo;
  atomic_store(&stop_flag, true);
}

// ========== 负载 ==========
struct thread_ctx {
  int id;
  pthread_t self;
  pid_t tid;
};

static inline void busy_loop_once(pid_t tgid, pid_t self_tid) {
  // 1) kill(..., 0) 仅做权限/存在性检查
  kill(tgid, 0);
  // 2) kill(..., SIGUSR1) —— 可能命中任意线程（主线程已屏蔽 SIGUSR1）
  kill(tgid, SIGUSR1);
  // 3) pthread_kill 发给自身的 pthread
  pthread_kill(pthread_self(), SIGUSR1);
  // 4) tgkill 发给自身 TID（避免打断主线程）
  if (self_tid > 0) tgkill_sys(tgid, self_tid, SIGUSR1);

  if (sleep_ns > 0) {
    struct timespec ts = { .tv_sec = 0, .tv_nsec = sleep_ns };
    nanosleep(&ts, NULL);
  }
}

static void* worker_fn(void* arg) {
  struct thread_ctx* ctx = (struct thread_ctx*)arg;
  ctx->tid = gettid_inline();

  // worker 独自接收 SIGUSR1：先解除继承的阻塞，再安装 handler
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  pthread_sigmask(SIG_UNBLOCK, &set, NULL);

  struct sigaction sa = {0};
  sa.sa_handler = sigusr1_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  const pid_t tgid = getpid();
  const pid_t self_tid = ctx->tid;

  while (!atomic_load(&stop_flag)) {
    busy_loop_once(tgid, self_tid);
  }
  return NULL;
}

// ========== 参数解析 & 用法 ==========
static void usage(const char* prog) {
  fprintf(stderr,
          "Usage: %s [--workers N] [--duration SEC] [--sleep-ns N]\n"
          "  --workers   创建 N 个线程并发触发(默认 1)\n"
          "  --duration  持续 SEC 秒; 0 或缺省表示直到 Ctrl-C\n"
          "  --sleep-ns  每轮循环后休眠 N 纳秒(默认 0=全速)\n",
          prog);
}

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--workers") && i + 1 < argc) {
      workers = atoi(argv[++i]);
      if (workers < 1) workers = 1;
    } else if (!strcmp(argv[i], "--duration") && i + 1 < argc) {
      duration_sec = atoi(argv[++i]);
      if (duration_sec < 0) duration_sec = 0;
    } else if (!strcmp(argv[i], "--sleep-ns") && i + 1 < argc) {
      sleep_ns = atol(argv[++i]);
      if (sleep_ns < 0) sleep_ns = 0;
    } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Unknown arg: %s\n", argv[i]);
      usage(argv[0]);
      return 1;
    }
  }

  // 主线程：屏蔽 SIGUSR1，避免被 kill()/tgkill() 打断
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  pthread_sigmask(SIG_BLOCK, &block, NULL);

  // 安装 SIGINT/SIGTERM 以便优雅退出
  struct sigaction si = {0};
  si.sa_handler = sigint_handler;
  sigemptyset(&si.sa_mask);
  sigaction(SIGINT, &si, NULL);
  sigaction(SIGTERM, &si, NULL);

  fprintf(stderr,
          "[sig_storm] PID=%d workers=%d duration=%ds sleep_ns=%ld\n",
          getpid(), workers, duration_sec, sleep_ns);

  // 创建工作线程
  struct thread_ctx* ctxs = calloc(workers, sizeof(*ctxs));
  if (!ctxs) { perror("calloc"); return 2; }

  for (int i = 0; i < workers; ++i) {
    ctxs[i].id = i;
    if (pthread_create(&ctxs[i].self, NULL, worker_fn, &ctxs[i]) != 0) {
      perror("pthread_create");
      return 3;
    }
  }

  // 计时：采用绝对时间，不受 EINTR 影响
  if (duration_sec > 0) {
    sleep_until_deadline_s(duration_sec);
    atomic_store(&stop_flag, true);
  }

  // 等待退出
  for (int i = 0; i < workers; ++i)
    pthread_join(ctxs[i].self, NULL);
  free(ctxs);

  fprintf(stderr, "[sig_storm] done.\n");
  return 0;
}
