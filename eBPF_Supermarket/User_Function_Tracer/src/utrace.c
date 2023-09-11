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
#include <sys/wait.h>

#include "elf.h"
#include "gdb.h"
#include "glob.h"
#include "log.h"
#include "symbol.h"
#include "thread_local.h"
#include "util.h"
#include "vector.h"
#include "vmem.h"

enum ARGP_SHORTOPT {
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

const char *argp_program_version = "eBPF-utrace 0.0";
const char argp_program_doc[] =
    "\nutrace: eBPF-based user function tracer for C/C++.\n"
    "\n"
    "Examples:\n"
    "  # trace the program specified by COMMAND\n"
    "  sudo build/utrace -c \"$COMMAND\"\n"
    "  # trace the program specified by PID\n"
    "  sudo build/utrace -p $PID\n";

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

extern bool debug;  // -d/--debug
static struct env {
  char *argv[12];                   // -c/-commond
  bool cpuid;                       // --cpuid
  bool flat;                        // --flat
  const char *func_pattern;         // -f/--function
  const char *lib_pattern;          // -l/--lib
  bool libname;                     // --libname
  int max_depth;                    // --max-depth
  const char *nest_lib_pattern;     // --nest-lib
  const char *no_func_pattern;      // no-function
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
      env.func_pattern = arg;
      break;
    case 'l':  // -l/--lib
      env.lib_pattern = arg;
      break;
    case OPT_LIBNAME:  // --libname
      env.libname = true;
      break;
    case OPT_MAX_DEPTH:  // --max-depth
      env.max_depth = atoi(arg);
      if (env.max_depth <= 0) {
        ERROR("The parameter for --max-depth should be greater than 0");
        exit(1);
      }
      break;
    case OPT_NEST_LIB:  // --nest-lib
      env.nest_lib_pattern = arg;
      break;
    case OPT_NO_FUNCTION:  // --no-function
      env.no_func_pattern = arg;
      break;
    case OPT_NO_ASLR:  // --no-randomize-addr
      env.no_aslr = true;
      break;
    case 'o':  // -o/--output
      env.output = fopen(arg, "w+");
      if (!env.output) {
        perror("fopen");
        exit(1);
      }
      break;
    case 'p':  // -p/--pid
      env.pid = atoi(arg);
      if (env.pid <= 0) {
        ERROR("The parameter for -p/--pid should be greater than 0");
        exit(1);
      }
      break;
    case OPT_TID:  // --tid
      env.tid = true;
      break;
    case OPT_TIME_FILTER:  // -time-filter
      env.min_duration = strduration2ns(arg);
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
  DEBUG("Attach uprobe to %s:%zx with pid = %d\n", exe, addr, pid);

  // Attach uprobe
  struct bpf_link *link = bpf_program__attach_uprobe(skel->progs.uprobe, false, pid, exe, addr);
  return link;
}

static struct bpf_link *uretprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *exe,
                                         size_t addr) {
  DEBUG("Attach uretprobe to %s:%zx with pid = %d\n", exe, addr, pid);

  // Attach uretprobe
  struct bpf_link *link = bpf_program__attach_uprobe(skel->progs.uretprobe, true, pid, exe, addr);
  return link;
}

static const char *default_skipped_func[] = {
    "c_start", "_start", "__libc_csu_init", "__libc_csu_fini", "_dl_relocate_static_pie",
};

static bool skip_symbol(const struct symbol *symbol) {
  // skip libcalls don't match lib_pattern
  if (env.libname && symbol->libname && !glob_match(symbol->libname, env.lib_pattern)) return true;
  // skip functions don't match func_pattern
  if (env.func_pattern && !glob_match(symbol->name, env.func_pattern)) return true;
  // skip functions match no_func_pattern
  if (env.no_func_pattern && glob_match(symbol->name, env.no_func_pattern)) return true;
  // skip some useless functions
  for (size_t i = 0; i < ARRAY_SIZE(default_skipped_func); i++)
    if (!strcmp(symbol->name, default_skipped_func[i])) return true;
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
    if (env.nest_lib_pattern && is_library(base_module_name) &&
        !glob_match(base_module_name, env.nest_lib_pattern))
      continue;
    vmem->module->symbol_table = symbol_table_init(module_name);
    if (!vmem->module->symbol_table) continue;
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
  enum FUNCSTATE state = thread_local_get_state(thread_local, index);

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

    const struct symbol *sym = vmem_table_symbolize(vmem_table, r->ustack[0]);
    if (sym) {
      struct profile_record prer = *r;
      prer.name = sym->name;
      prer.libname = sym->libname;
      if (thread_local_record_size(thread_local, index) &&
          thread_local_get_record_back(thread_local, index)->ustack_sz + 1 != prer.ustack_sz)
        thread_local_pop_record(thread_local, index);
      thread_local_push_record(thread_local, index, &prer);
      thread_local_set_state(thread_local, index, STATE_EXEC);
    } else {
      // ignore
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  struct utrace_bpf *skel = NULL;
  struct ring_buffer *records = NULL;
  struct vector *bpf_links = NULL;  // Store all bpf links

  struct rlimit old_rlim;
  const char *program;
  pid_t pid;
  int err;

  env.func_pattern = "*";     // Trace all functions by default
  env.lib_pattern = "*";      // Trace all libcalls by default
  env.nest_lib_pattern = "";  // Don't trace libraries by default
  env.max_depth = MAX_STACK_SIZE;
  env.no_func_pattern = "";
  env.output = stderr;  // Output to stderr by default
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (!env.argv[0] && !env.pid) {
    exit(1);
  } else if (err) {
    return err;
  }

  // Ensure root permission
  if (geteuid() != 0) {
    ERROR("Failed to run %s: permission denied\n", argv[0]);
    return 1;
  }

  // Register handlers for Ctrl-C
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  // Set up libbpf errors and debug info callback
  libbpf_set_print(libbpf_print_fn);

  // Load and verify BPF program
  skel = utrace_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  skel->rodata->max_depth = env.max_depth;
  skel->rodata->min_duration = env.min_duration;

  err = utrace_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  // Set up ring buffer polling
  records = ring_buffer__new(bpf_map__fd(skel->maps.records), handle_event, NULL, NULL);
  if (!records) {
    err = 1;
    ERROR("Failed to create ring buffer\n");
    goto cleanup;
  }

  // Save the old rlimit
  if (getrlimit(RLIMIT_NOFILE, &old_rlim) == -1) {
    perror("getrlimit");
    exit(1);
  }
  struct rlimit rlim = {
      .rlim_cur = 1 << 20,
      .rlim_max = 1 << 20,
  };
  // Maximize the number of file descriptors
  if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
    perror("setrlimit");
    exit(1);
  }

  bpf_links = vector_init(sizeof(struct bpf_link *));
  // Store local states for each thread
  thread_local = thread_local_init();

  // Set pid and/or program
  if (env.pid) {
    pid = env.pid;
    vmem_table = vmem_table_init(pid);
    program = vmem_table_get_prog_name(vmem_table);
  } else {
    program = resolve_full_path(env.argv[0]);
  }
  if (!program) {
    ERROR("Cannot find the traced program");
    goto cleanup;
  }

  if (env.pid) {
    int cnt = bpf_probe_attach(skel, bpf_links, pid);
    DEBUG("Attached total %d uprobes\n", cnt);

    if (utrace_bpf__attach(skel) != 0) {
      ERROR("Failed to attach BPF skeleton\n");
      goto cleanup;
    }
  } else {
    size_t break_addr = get_entry_address(program);
    if (!break_addr) {
      ERROR("Can not find entry address for breaking");
      exit(1);
    }

    pid = fork();
    if (pid < 0) {
      perror("fork");
      exit(1);
    } else if (pid == 0) {
      if (env.no_aslr) personality(ADDR_NO_RANDOMIZE);
      ptrace(PTRACE_TRACEME, 0, 0, 0);
      if (env.user) {
        struct passwd *user_info = getpwnam(env.user);
        if (!user_info) {
          ERROR("Invalid username: %s\n", env.user);
          exit(1);
        }
        if (setuid(user_info->pw_uid)) {
          perror("setuid");
          exit(1);
        }
      }
      execv(program, env.argv);
      perror("execv");
      exit(1);
    } else {
      struct gdb *gdb = gdb_init(pid);
      gdb_wait_for_signal(gdb);

      vmem_table = vmem_table_init(pid);
      if (break_addr >= BASE_ADDR) break_addr -= BASE_ADDR;
      break_addr += vmem_table_get_prog_st_addr(vmem_table);
      DEBUG("Break address: %zx\n", break_addr);

      gdb_enable_breakpoint(gdb, break_addr);
      gdb_continue_execution(gdb);
      gdb_wait_for_signal(gdb);

      int cnt = bpf_probe_attach(skel, bpf_links, pid);
      DEBUG("Attached total %d uprobes\n", cnt);

      if (utrace_bpf__attach(skel) != 0) {
        ERROR("Failed to attach BPF skeleton\n");
        goto cleanup;
      }

      gdb_disable_breakpoint(gdb, break_addr);
      gdb_free(gdb);
    }
  }

  LOG(stderr, "Tracing...\n");
  log_footer(stderr, env.cpuid, env.tid, env.timestamp);
  if (!env.flat) log_header(env.output, env.cpuid, env.tid, env.timestamp);

  // Process events
  while (!exiting) {
    err = ring_buffer__poll(records, 100 /* timeout, ms */);
    // Ctrl-C will cause -EINTR
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      ERROR("Error polling perf buffer: %d\n", err);
      break;
    }
    if (err == 0) {
      if (env.pid) {
        if (kill(pid, 0)) break;
      } else {
        int wstatus;
        pid_t ret = waitpid(pid, &wstatus, WNOHANG);
        if (ret > 0)
          break;
        else if (ret < 0) {
          ERROR("Exec %s error\n", program);
          break;
        }
      }
    }
  }

  log_footer(stderr, env.cpuid, env.tid, env.timestamp);

cleanup:
  // Clean up
  ring_buffer__free(records);

  LOG(stderr, "Detaching...\n");
  for (size_t i = 0; i < vector_size(bpf_links); i++) {
    bpf_link__destroy(*((struct bpf_link **)vector_get(bpf_links, i)));
  }

  vector_free(bpf_links);

  utrace_bpf__destroy(skel);

  thread_local_free(thread_local);
  vmem_table_free(vmem_table);

  if (setrlimit(RLIMIT_NOFILE, &old_rlim) == -1) {
    perror("setrlimit");
    exit(1);
  }

  return err ? abs(err) : 0;
}
