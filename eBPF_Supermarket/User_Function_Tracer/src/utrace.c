// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: jinyufeng2000@gmail.com
//
// 基于eBPF的用户态函数观测主程序

#include "utrace.h"
#include "utrace.skel.h"

#include <argp.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <pwd.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "elf.h"
#include "gdb.h"
#include "glob.h"
#include "log.h"
#include "symbol.h"
#include "thread_local.h"
#include "util.h"
#include "vector.h"
#include "vmem.h"

enum {
  OPT_CPUID = 0x1234,
  OPT_FLAT,
  OPT_LIB,
  OPT_LIBNAME,
  OPT_MAX_DEPTH,
  OPT_NEST_LIB,
  OPT_NO_ASLR,
  OPT_NO_FUNCTION,
  OPT_TID,
  OPT_TIME_FILTER,
  OPT_TIMESTAMP,
};

const char *argp_program_version = "eBPF-utrace 0.1";
const char argp_program_doc[] =
    "\neBPF-utrace: eBPF-based user function tracer for C/C++.\n"
    "\n"
    "Examples:\n"
    "  # trace the program specified by COMMAND\n"
    "  $ sudo build/utrace -c \"$COMMAND\"\n"
    "  # trace the program specified by PID\n"
    "  $ sudo build/utrace -p $PID\n";

static const struct argp_option opts[] = {
    {"command", 'c', "COMMAND", 0,
     "Specify the COMMAND to run the traced program (format: \"program arguments\")", 0},
    {"cpuid", OPT_CPUID, NULL, 0, "Display CPU ID", 0},
    {"debug", 'd', NULL, 0, "Show debug information", 0},
    {"flat", OPT_FLAT, NULL, 0, "Display in a flat output format", 0},
    {"function", 'f', "FUNC_PATTERN", 0,
     "Only trace functions matching FUNC_PATTERN (in glob format, default \"*\")", 0},
    {"lib", 'l', "LIB_PATTERN", 0,
     "Only trace libcalls to libraries matching LIB_PATTERN (in glob format, default \"*\")", 0},
    {"libname", OPT_LIBNAME, NULL, 0, "Append libname to symbol name", 0},
    {"max-depth", OPT_MAX_DEPTH, "DEPTH", 0, "Hide functions with stack depths greater than DEPTH",
     0},
    {"nest-lib", OPT_NEST_LIB, "NEST_LIB_PATTERN", 0,
     "Also trace functions in libraries matching LIB_PATTERN (default \"\")", 0},
    {"no-function", OPT_NO_FUNCTION, "FUNC_PATTERN", 0,
     "Don't trace functions matching FUNC_PATTERN (in glob format, default \"\")", 0},
    {"no-randomize-addr", OPT_NO_ASLR, NULL, 0, "Disable address space layout randomization (ASLR)",
     0},
    {"output", 'o', "OUTPUT_FILE", 0, "Send trace output to OUTPUT_FILE instead of stderr", 0},
    {"pid", 'p', "PID", 0, "PID of the traced program", 0},
    {"tid", OPT_TID, NULL, 0, "Display thread ID", 0},
    {"time-filter", OPT_TIME_FILTER, "TIME", 0, "Hide functions when they run less than TIME", 0},
    {"timestamp", OPT_TIMESTAMP, NULL, 0, "Display timestamp", 0},
    {"user", 'u', "USERNAME", 0, "Run the specified command as USERNAME", 0},
    {}};

bool debug;  // -d/--debug
static struct env {
  char *argv[12];                   // -c/-commond
  bool cpuid;                       // --cpuid
  bool flat;                        // --flat
  char *func_pattern;               // -f/--function
  char *lib_pattern;                // -l/--lib
  bool libname;                     // --libname
  unsigned int max_depth;           // --max-depth
  char *nest_lib_pattern;           // --nest-lib
  char *no_func_pattern;            // no-function
  bool no_aslr;                     // --no-randomize-addr
  FILE *output;                     // -o/--output
  pid_t pid;                        // -p/--pid
  bool tid;                         // --tid
  bool timestamp;                   // --timestamp
  unsigned long long min_duration;  // --time-filter
  char *user;                       // -u/--user
} env;

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  switch (key) {
    case 'c':  // -c/--command
      for (int i = 0, len = strlen(arg), cnt = 0, j; i < len; i++) {
        if (arg[i] != ' ') {
          j = i + 1;
          while (j < len && arg[j] != ' ') ++j;
          arg[j] = '\0';
          env.argv[cnt] = strdup(arg + i);
          env.argv[++cnt] = NULL;
          arg[j] = ' ';
          i = j;
        }
      }
      break;
    case OPT_CPUID:  // --cpuid
      env.cpuid = true;
      break;
    case 'd':  // -d/--debug
      debug = true;
      break;
    case OPT_FLAT:  // --flat
      env.flat = true;
      break;
    case 'f':  // -f/--function
      if (env.func_pattern) {
        env.func_pattern = restrcat(env.func_pattern, ",");
        env.func_pattern = restrcat(env.func_pattern, arg);
      } else {
        env.func_pattern = strdup(arg);
      }
      break;
    case 'l':  // -l/--lib
      if (env.lib_pattern) {
        env.lib_pattern = restrcat(env.lib_pattern, ",");
        env.lib_pattern = restrcat(env.lib_pattern, arg);
      } else {
        env.lib_pattern = strdup(arg);
      }
      break;
    case OPT_LIBNAME:  // --libname
      env.libname = true;
      break;
    case OPT_MAX_DEPTH:  // --max-depth
      env.max_depth = atoi(arg);
      if (env.max_depth <= 0) {
        ERROR("The parameter for --max-depth should be greater than 0");
        return 1;
      }
      break;
    case OPT_NEST_LIB:  // --nest-lib
      if (env.nest_lib_pattern) {
        env.nest_lib_pattern = restrcat(env.nest_lib_pattern, ",");
        env.nest_lib_pattern = restrcat(env.nest_lib_pattern, arg);
      } else {
        env.nest_lib_pattern = strdup(arg);
      }
      break;
    case OPT_NO_FUNCTION:  // --no-function
      env.no_func_pattern = arg;
      if (env.lib_pattern) {
        env.no_func_pattern = restrcat(env.no_func_pattern, ",");
        env.no_func_pattern = restrcat(env.no_func_pattern, arg);
      } else {
        env.no_func_pattern = strdup(arg);
      }
      break;
    case OPT_NO_ASLR:  // --no-randomize-addr
      env.no_aslr = true;
      break;
    case 'o':  // -o/--output
      env.output = fopen(arg, "w+");
      if (env.output == NULL) die("fopen");
      break;
    case 'p':  // -p/--pid
      env.pid = atoi(arg);
      if (env.pid <= 0) {
        ERROR("The parameter for -p/--pid should be greater than 0");
        return 1;
      }
      break;
    case OPT_TID:  // --tid
      env.tid = true;
      break;
    case OPT_TIME_FILTER:  // -time-filter
      env.min_duration = duration_str2ns(arg);
      break;
    case OPT_TIMESTAMP:  // --timestamp
      env.timestamp = true;
      break;
    case 'u':  // -u/--user
      env.user = arg;
      break;
    case ARGP_KEY_ARG:
      argp_usage(state);
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  if (level == LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static void sig_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) exiting = true;
}

static struct bpf_link *uprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *exe,
                                      size_t addr) {
  DEBUG("Attach uprobe to %s:%zx with pid = %d", exe, addr, pid);

  // Attach uprobe
  struct bpf_link *link = bpf_program__attach_uprobe(skel->progs.uprobe, false, pid, exe, addr);
  return link;
}

static struct bpf_link *uretprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *exe,
                                         size_t addr) {
  DEBUG("Attach uretprobe to %s:%zx with pid = %d", exe, addr, pid);

  // Attach uretprobe
  struct bpf_link *link = bpf_program__attach_uprobe(skel->progs.uretprobe, true, pid, exe, addr);
  return link;
}

static const char *default_skipped_func[] = {
    "c_start", "_start", "__libc_csu_init", "__libc_csu_fini", "__libc_start_main", "_dl_relocate_static_pie", "__x86.get_pc_thunk.bx",
};

static bool skip_symbol(const struct symbol *symbol) {
  // skip libcalls don't match lib_pattern
  if (symbol->libname && !glob_match_ext(symbol->libname, env.lib_pattern))
    return true;
  // skip functions don't match func_pattern
  if (!glob_match_ext(symbol->name, env.func_pattern)) return true;
  // skip functions match no_func_pattern
  if (glob_match_ext(symbol->name, env.no_func_pattern)) return true;
  // skip some useless functions
  for (size_t i = 0; i < ARRAY_SIZE(default_skipped_func); i++)
    if (strcmp(symbol->name, default_skipped_func[i]) == 0) return true;
  return false;
}

struct vmem_table *vmem_table;
struct thread_local *thread_local;
static int bpf_probe_attach(struct utrace_bpf *skel, struct vector *bpf_links, pid_t pid) {
  int probe_cnt = 0;
  struct bpf_link *link;

  vmem_table = vmem_table_init(pid);
  for (size_t i = 0; i < vmem_table_size(vmem_table); i++) {
    const struct vmem *vmem = vmem_table_get(vmem_table, i);
    if (i > 0 && vmem_table_get(vmem_table, i - 1)->module == vmem->module) continue;  // duplicate
    const char *module_name = module_get_name(vmem->module);
    const char *base_module_name = base_name(module_name);
    // only trace libraries matching env.nest_lib_pattern
    if (is_library(base_module_name) &&
        !glob_match_ext(base_module_name, env.nest_lib_pattern))
      continue;
    if (!module_init_symbol_table(vmem->module)) continue;
    for (size_t j = 0; j < symbol_table_size(vmem->module->symbol_table); j++) {
      const struct symbol *sym = symbol_table_get(vmem->module->symbol_table, j);
      if (!skip_symbol(sym)) {
        link = uprobe_attach(skel, pid, module_name, sym->addr);
        ++probe_cnt;
        vector_push_back(bpf_links, &link);
        link = uretprobe_attach(skel, pid, module_name, sym->addr);
        vector_push_back(bpf_links, &link);
        ++probe_cnt;
      }
    }
  }
  return probe_cnt;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  (void)ctx;
  (void)data_sz;

  struct profile_record *r = data;

  unsigned int index = thread_local_get_index(thread_local, r->tid);
  enum FUNC_STATE state = thread_local_get_state(thread_local, index);

  if (r->ret) {
    if (state == STATE_EXEC) {
      struct profile_record *prer = thread_local_get_record_back(thread_local, index);
      if (env.min_duration) {
        while (prer->ustack_sz != r->ustack_sz) {
          if (!thread_local_record_size(thread_local, index)) {
            prer = NULL;
            break;
          } else {
            thread_local_pop_record(thread_local, index);
            prer = thread_local_get_record_back(thread_local, index);
          }
        }
        for (size_t i = 0; i + 1 < thread_local_record_size(thread_local, index); i++) {
          struct profile_record *prer = thread_local_get_record(thread_local, index, i);
          if (prer->tid) {
            log_trace_data(env.output, env.cpuid ? &(prer->cpu_id) : NULL,
                           env.tid ? &(prer->tid) : NULL, env.timestamp ? &(prer->timestamp) : NULL,
                           0, prer->ustack_sz, prer->name, prer->libname, prer->ret, state,
                           env.flat, env.libname);
            prer->tid = 0;  // mark
          }
        }
      }

      if (prer) {
        log_trace_data(env.output, env.cpuid ? &(prer->cpu_id) : NULL,
                       env.tid ? &(prer->tid) : NULL, env.timestamp ? &(prer->timestamp) : NULL,
                       r->duration_ns, prer->ustack_sz, prer->name, prer->libname, r->ret,
                       prer->tid ? state : STATE_EXIT, env.flat, env.libname);
        thread_local_pop_record(thread_local, index);
        thread_local_set_state(thread_local, index, STATE_EXIT);
      }
    } else if (state == STATE_EXIT) {
      struct profile_record *prer = thread_local_get_record_back(thread_local, index);
      log_trace_data(env.output, env.cpuid ? &(r->cpu_id) : NULL, env.tid ? &(r->tid) : NULL,
                     env.timestamp ? &(r->timestamp) : NULL, r->duration_ns, r->ustack_sz,
                     prer->name, prer->libname, r->ret, state, env.flat, env.libname);
      thread_local_pop_record(thread_local, index);
      thread_local_set_state(thread_local, index, STATE_EXIT);
    }
  } else {
    if (state == STATE_EXEC) {
      if (!env.min_duration) {
        struct profile_record *prer = thread_local_get_record_back(thread_local, index);
        log_trace_data(env.output, env.cpuid ? &(prer->cpu_id) : NULL,
                       env.tid ? &(prer->tid) : NULL, env.timestamp ? &(prer->timestamp) : NULL, 0,
                       prer->ustack_sz, prer->name, prer->libname, r->ret, state, env.flat,
                       env.libname);
      }
    }

    const struct symbol *symbol = vmem_table_symbolize(vmem_table, r->ustack[0]);
    if (symbol) {
      struct profile_record curr = *r;
      curr.name = symbol->name;  // TODO refactor
      curr.libname = symbol->libname;
      if (thread_local_record_size(thread_local, index) &&
          thread_local_get_record_back(thread_local, index)->ustack_sz + 1 != curr.ustack_sz)
        thread_local_pop_record(thread_local, index);
      thread_local_push_record(thread_local, index, &curr);
      thread_local_set_state(thread_local, index, STATE_EXEC);
    } else {
      // ignore
    }
  }
  return 0;
}

#define fail(fmt, ...)         \
  do {                         \
    ERROR(fmt, ##__VA_ARGS__); \
    err = 1;                   \
    goto cleanup;              \
  } while (0)

int main(int argc, char **argv) {
  int err = 0;

  struct utrace_bpf *skel = NULL;
  struct ring_buffer *records = NULL;
  struct vector *bpf_links = NULL;  // Store all bpf links

  char *program = NULL;
  pid_t pid;

  env.max_depth = MAX_STACK_SIZE;
  env.output = stderr;  // Output to stderr by default
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err) {
    goto cleanup;
  } else if (!env.argv[0] && !env.pid) {
    fail("Please specify the traced program or its pid");
  }
  if (!env.func_pattern) env.func_pattern = strdup("*");         // Trace all functions by default
  if (!env.lib_pattern) env.lib_pattern = strdup("*");           // Trace all libcalls by default
  if (!env.nest_lib_pattern) env.nest_lib_pattern = strdup("");  // Don't trace libraries by default
  if (!env.no_func_pattern) env.no_func_pattern = strdup(""); 

  // Ensure root permission
  if (geteuid() != 0) fail("Failed to run %s: permission denied", argv[0]);

  // Register handlers for Ctrl-C
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  // Set up libbpf errors and debug info callback
  libbpf_set_print(libbpf_print_fn);

  // Load and verify BPF program
  skel = utrace_bpf__open();
  if (!skel) fail("Failed to open and load BPF skeleton");

  skel->rodata->max_depth = env.max_depth;
  skel->rodata->min_duration = env.min_duration;

  err = utrace_bpf__load(skel);
  if (err) fail("Failed to load and verify BPF skeleton");

  // Set up ring buffer polling
  records = ring_buffer__new(bpf_map__fd(skel->maps.records), handle_event, NULL, NULL);
  if (!records) fail("Failed to create ring buffer");

  // Save the old rlimit
  struct rlimit old_rlim;
  if (getrlimit(RLIMIT_NOFILE, &old_rlim) == -1) die("getrlimit");
  struct rlimit rlim = {
      .rlim_cur = 1 << 20,
      .rlim_max = 1 << 20,
  };
  // Maximize the number of file descriptors
  if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) die("setrlimit");

  bpf_links = vector_init(sizeof(struct bpf_link *));
  // Store local states for each thread
  thread_local = thread_local_init();

  // Set pid and/or program
  if (env.pid) {
    pid = env.pid;
    vmem_table = vmem_table_init(pid);
    program = strdup(vmem_table_get_prog_name(vmem_table));
  } else {
    program = resolve_full_path(env.argv[0]);
  }
  if (!program) fail("Cannot find the traced program");

  if (env.pid) {
    int cnt = bpf_probe_attach(skel, bpf_links, pid);
    DEBUG("Attached total %d uprobes", cnt);

    if (utrace_bpf__attach(skel) != 0) fail("Failed to attach BPF skeleton");
  } else {
    size_t break_addr = get_entry_address(program);
    if (!break_addr) fail("Can not find entry address for breaking");

    pid = fork();
    if (pid < 0) {
      die("fork");
    } else if (pid == 0) {
      if (env.no_aslr) personality(ADDR_NO_RANDOMIZE);
      if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) die("perror");
      if (env.user) {
        struct passwd *user_info = getpwnam(env.user);
        if (!user_info) fail("Invalid username: %s", env.user);
        if (setuid(user_info->pw_uid)) die("setuid");
      }
      execv(program, env.argv);
      die("execv");
    } else {
      struct gdb *gdb = gdb_init(pid);
      if (gdb_wait_for_signal(gdb) == -1) die("perror");

      vmem_table = vmem_table_init(pid);
      break_addr = resolve_addr(break_addr);
      break_addr += vmem_table_get_prog_st_addr(vmem_table);
      DEBUG("Break address: %zx", break_addr);

      if (gdb_enable_breakpoint(gdb, break_addr) == -1) die("perror");
      if (gdb_continue_execution(gdb) == -1) die("perror");
      if (gdb_wait_for_signal(gdb) == -1) die("perror");

      int cnt = bpf_probe_attach(skel, bpf_links, pid);
      DEBUG("Attached total %d uprobes", cnt);

      if (utrace_bpf__attach(skel) != 0) fail("Failed to attach BPF skeleton");

      if (gdb_disable_breakpoint(gdb, break_addr) == -1) die("perror");
      if (gdb_detach(gdb) == -1) die("perror");
      gdb_free(gdb);
    }
  }

  LOG(stderr, "Tracing...\n");
  log_footer(stderr, env.cpuid, env.tid, env.timestamp);
  if (!env.flat) log_header(env.output, env.cpuid, env.tid, env.timestamp);

  // Process events
  while (!exiting) {
    err = ring_buffer__poll(records, 100 /* timeout (ms) */);
    // Ctrl-C will cause -EINTR
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fail("Error polling perf buffer: %d", err);
    } else if (err == 0) {
      if (env.pid) {
        if (kill(pid, 0)) break;
      } else {
        int wstatus;
        pid_t ret = waitpid(pid, &wstatus, WNOHANG);
        if (ret > 0) {
          break;
        } else if (ret < 0) {
          fail("Exec %s error", program);
        }
      }
    }
  }

  log_footer(stderr, env.cpuid, env.tid, env.timestamp);

cleanup:
  free(env.func_pattern);
  free(env.lib_pattern);
  free(env.nest_lib_pattern);
  free(env.no_func_pattern);
  free(program);

  ring_buffer__free(records);

  if (bpf_links && !vector_empty(bpf_links)) {
    LOG(stderr, "Detaching...\n");
    for (size_t i = 0; i < vector_size(bpf_links); i++) {
      bpf_link__destroy(*((struct bpf_link **)vector_get(bpf_links, i)));
    }
  }

  vector_free(bpf_links);

  utrace_bpf__destroy(skel);

  thread_local_free(thread_local);
  vmem_table_free(vmem_table);

  if (geteuid() == 0 && setrlimit(RLIMIT_NOFILE, &old_rlim) == -1) die("setrlimit");

  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
