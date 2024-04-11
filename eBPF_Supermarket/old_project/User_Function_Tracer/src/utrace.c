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
// Main function of eBPF-utrace

#include "utrace.h"
#include "utrace.skel.h"

#include <argp.h>
#include <bpf/libbpf.h>
#include <pwd.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "elf.h"
#include "env.h"
#include "gdb.h"
#include "glob.h"
#include "log.h"
#include "record.h"
#include "report.h"
#include "util.h"
#include "vmem.h"

// used as dummy short options in argp
enum {
  OPT_AVG_SELF = 0x1234,
  OPT_AVG_TOTAL,
  OPT_FLAT,
  OPT_FORMAT,
  OPT_LIB,
  OPT_LIBNAME,
  OPT_MAX_DEPTH,
  OPT_NEST_LIB,
  OPT_NO_ASLR,
  OPT_NO_FUNCTION,
  OPT_NO_LIB,
  OPT_PERCENT_SELF,
  OPT_PERCENT_TOTAL,
  OPT_RECORD,
  OPT_REPORT,
  OPT_SAMPLE_TIME,
  OPT_TID,
  OPT_TID_FILTER,
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
  { "avg-self", OPT_AVG_SELF, NULL, 0, "Show average/min/max of self function time in report", 0 },
  { "avg-total", OPT_AVG_TOTAL, NULL, 0, "Show average/min/max of total function time in report",
    0 },
  { "command", 'c', "COMMAND", 0,
    "Specify the COMMAND to run the traced program (format: \"program arguments\")", 0 },
  { "debug", 'd', NULL, 0, "Show debug information", 0 },
  { "flat", OPT_FLAT, NULL, 0, "Display in a flat output format", 0 },
  { "format", OPT_FORMAT, "FORMAT", 0,
    "Use FORMAT (summary, chrome, flame-graph and call-graph, default is call-graph) in report",
    0 },
  { "function", 'f', "FUNC_PATTERN", 0,
    "Only trace functions matching FUNC_PATTERN (in glob format, default \"*\")", 0 },
  { "lib", 'l', "LIB_PATTERN", 0,
    "Only trace libcalls to libraries matching LIB_PATTERN (in glob format, default \"*\")", 0 },
  { "libname", OPT_LIBNAME, NULL, 0, "Append libname to symbol name", 0 },
  { "max-depth", OPT_MAX_DEPTH, "DEPTH", 0, "Hide functions with stack depths greater than DEPTH",
    0 },
  { "nest-lib", OPT_NEST_LIB, "NEST_LIB_PATTERN", 0,
    "Also trace functions in libraries matching LIB_PATTERN (default \"\")", 0 },
  { "no-function", OPT_NO_FUNCTION, "NO_FUNC_PATTERN", 0,
    "Don't trace functions matching NO_FUNC_PATTERN (in glob format, default \"\")", 0 },
  { "no-lib", OPT_NO_LIB, "NO_LIB_PATTERN", 0,
    "Don't trace libcalls to libraries matching NO_LIB_PATTERN (in glob format, default \"\")", 0 },
  { "no-randomize-addr", OPT_NO_ASLR, NULL, 0, "Disable address space layout randomization (ASLR)",
    0 },
  { "output", 'o', "OUTPUT_FILE", 0, "Send trace output to OUTPUT_FILE instead of stderr", 0 },
  { "pid", 'p', "PID", 0, "PID of the traced program", 0 },
  { "percent-self", OPT_PERCENT_SELF, NULL, 0, "Show percentage of self function time in report",
    0 },
  { "percent-total", OPT_PERCENT_TOTAL, NULL, 0, "Show percentage of total function time in report",
    0 },
  { "record", OPT_RECORD, NULL, 0, "Save the trace data", 0 },
  { "report", OPT_REPORT, NULL, 0, "Analyze the pre-saved trace data", 0 },
  { "sample-time", OPT_SAMPLE_TIME, "TIME", 0,
    "Apply TIME as the sampling time (defaut 1us) when generating flame graph in report", 0 },
  { "tid", OPT_TID, NULL, 0, "Display thread ID", 0 },
  { "tid-filter", OPT_TID_FILTER, "TID", 0, "Only show functions in TID", 0 },
  { "time-filter", OPT_TIME_FILTER, "TIME", 0, "Hide functions when they run less than TIME", 0 },
  { "timestamp", OPT_TIMESTAMP, NULL, 0, "Display timestamp", 0 },
  { "user", 'u', "USERNAME", 0, "Run the specified command as USERNAME", 0 },
  {}
};

bool debug; /**< -d/--debug */
struct env env;
static struct record *record;
static struct printer *printer;

// parse command line arguments to set the struct `env`
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  static int tid;  // for --tid-filter
  switch (key) {
    case OPT_AVG_SELF:
      env.avg_self = true;
      break;
    case OPT_AVG_TOTAL:
      env.avg_total = true;
      break;
    case 'c':  // -c/--command
      for (int i = 0, len = strlen(arg), argc = 0, j; i < len; i++) {
        if (arg[i] != ' ') {
          j = i + 1;
          while (j < len && arg[j] != ' ') ++j;
          if (j < len) arg[j] = '\0';  // overwrite the current ' ' for the below std::strdup
          env.argv[argc] = strdup(arg + i);
          env.argv[++argc] = NULL;    // argv[argc] should be NULL
          if (j < len) arg[j] = ' ';  // restore the ' '
          i = j;
        }
      }
      break;
    case 'd':  // -d/--debug
      debug = true;
      break;
    case OPT_FLAT:  // --flat
      env.flat = true;
      break;
    case OPT_FORMAT:  // --format
      if (!strncmp(arg, "summary", 7))
        env.format = SUMMARY;
      else if (!strncmp(arg, "chrome", 6))
        env.format = CHROME;
      else if (!strncmp(arg, "flame-graph", 11))
        env.format = FLAME_GRAPH;
      // otherwise, env.format is the default CALL_GRAPH
      break;
    case 'f':                  // -f/--function
      if (env.func_pattern) {  // join multiple regular glob patterns with ','
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
      env.show_libname = true;
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
      if (env.no_func_pattern) {
        env.no_func_pattern = restrcat(env.no_func_pattern, ",");
        env.no_func_pattern = restrcat(env.no_func_pattern, arg);
      } else {
        env.no_func_pattern = strdup(arg);
      }
      break;
    case OPT_NO_LIB:  // --no-lib
      if (env.no_lib_pattern) {
        env.no_lib_pattern = restrcat(env.no_lib_pattern, ",");
        env.no_lib_pattern = restrcat(env.no_lib_pattern, arg);
      } else {
        env.no_lib_pattern = strdup(arg);
      }
      break;
    case OPT_NO_ASLR:  // --no-randomize-addr
      env.no_aslr = true;
      break;
    case 'o':  // -o/--output
               // open and truncate the file; or create a new file if it doesn't exist
      env.out = fopen(arg, "w+");
      if (!env.out) die("fopen");
      break;
    case 'p':  // -p/--pid
      env.pid = atoi(arg);
      if (env.pid <= 0) {
        ERROR("The parameter for -p/--pid should be greater than 0");
        return 1;
      }
      break;
    case OPT_PERCENT_SELF:  // --percent-self
      env.percent_self = true;
      break;
    case OPT_PERCENT_TOTAL:  // --percent-total
      env.percent_total = true;
      break;
    case OPT_RECORD:  // --record
      env.do_record = true;
      break;
    case OPT_REPORT:  // --report
      env.do_report = true;
      break;
    case OPT_SAMPLE_TIME:  // --sample-time
      env.sample_time_ns = duration_str2ns(arg);
      if (!env.sample_time_ns) {
        ERROR(
            "The parameter for --sample_time is ill-formed and it should be greater than \"0ns\"");
        return 1;
      }
      break;
    case OPT_TID:  // --tid
      env.show_tid = true;
      break;
    case OPT_TID_FILTER:  // --tid-filter
      tid = atoi(arg);
      vector_push_back(env.tids, &tid);
      break;
    case OPT_TIME_FILTER:  // -time-filter
      env.min_duration = duration_str2ns(arg);
      break;
    case OPT_TIMESTAMP:  // --timestamp
      env.show_timestamp = true;
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

// exit immediately after receiving `Ctrl-C` or `kill 15`
static volatile bool exiting = false;
static void sig_handler(int sig) {
  if (sig == SIGINT || sig == SIGTERM) exiting = true;
}

// attach a uprobe to address `addr` of the program `prog` with process ID `pid`
static struct bpf_link *uprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *prog,
                                      size_t addr) {
  DEBUG("Attach uprobe to %s:%zx with pid = %d", prog, addr, pid);
  struct bpf_link *link = bpf_program__attach_uprobe(skel->progs.uprobe, false, pid, prog, addr);
  return link;
}

// attach a uretprobe to address `addr` of the program `exe` with process ID `pid`
static struct bpf_link *uretprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *prog,
                                         size_t addr) {
  DEBUG("Attach uretprobe to %s:%zx with pid = %d", prog, addr, pid);
  struct bpf_link *link = bpf_program__attach_uprobe(skel->progs.uretprobe, true, pid, prog, addr);
  return link;
}

// skip these useless functions
static const char *default_skipped_func[] = {
  "c_start",
  "_start",
  "__stack_chk_fail",
  "__libc_csu_init",
  "__libc_csu_fini",
  "__libc_start_main",
  "_dl_relocate_static_pie",
  "__x86.get_pc_thunk.bx",
};

// check whether the `symbol` should be skipped
static bool skip_symbol(const struct symbol *symbol) {
  // skip libcalls don't match lib_pattern
  const char *libname = symbol->libname ? symbol->libname : "";
  if (!glob_match_ext(libname, env.lib_pattern)) return true;
  // skip libcalls match no_lib_pattern
  if (env.no_lib_pattern && glob_match_ext(libname, env.no_lib_pattern)) return true;
  // skip functions don't match func_pattern
  if (!glob_match_ext(symbol->name, env.func_pattern)) return true;
  // skip functions match no_func_pattern
  if (env.no_func_pattern && glob_match_ext(symbol->name, env.no_func_pattern)) return true;
  // skip some useless functions
  for (unsigned long i = 0; i < ARRAY_SIZE(default_skipped_func); i++)
    if (strcmp(symbol->name, default_skipped_func[i]) == 0) return true;
  return false;
}

static struct vmem_table *vmem_table;
static struct thread_local *thread_local;

// attach uprobes to all functions in process `pid` that need to be traced
static int bpf_probe_attach(struct utrace_bpf *skel, struct vector *bpf_links, pid_t pid) {
  int probe_cnt = 0;
  struct bpf_link *link;

  vmem_table = vmem_table_init(pid);
  for (size_t i = 0; i < vmem_table_size(vmem_table); i++) {
    const struct vmem *vmem = vmem_table_get(vmem_table, i);
    if (i > 0 && strcmp(module_get_name(vmem_table_get(vmem_table, i - 1)->module),
                        module_get_name(vmem->module)) == 0)
      continue;  // duplicate modules
    const char *module_name = module_get_name(vmem->module);
    const char *base_module_name = base_name(module_name);
    // only trace into libraries matching nest_lib_pattern
    if (is_library(base_module_name) && !glob_match_ext(base_module_name, env.nest_lib_pattern))
      continue;
    if (!module_symbol_table_init(vmem->module)) continue;
    for (size_t j = 0; j < symbol_table_size(vmem->module->symbol_table); j++) {
      const struct symbol *sym = symbol_table_get(vmem->module->symbol_table, j);
      if (!skip_symbol(sym)) {
        link = uprobe_attach(skel, pid, module_name, sym->addr);
        ++probe_cnt;
        vector_push_back(bpf_links, &link);
        link = uretprobe_attach(skel, pid, module_name, sym->addr);
        ++probe_cnt;
        vector_push_back(bpf_links, &link);
      }
    }
  }
  return probe_cnt;
}

// handle the traced data recorded and sent by kernel
static int handle_event(void *ctx, void *data, size_t data_sz) {
  (void)ctx;
  (void)data_sz;
  struct user_record user_record = {
    .krecord = *((struct kernel_record *)data),
  };
  print_trace(printer, vmem_table, thread_local, record, &user_record);
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
  struct vector *bpf_links = NULL;  // maintain all attached bpf links

  char *program = NULL;  // malloced from heap
  pid_t pid;

  struct rlimit old_rlim;
  bool has_get_rlimit = false;
  int perf_event_max_stack = -1;

  env.max_depth = MAX_STACK_SIZE;
  env.out = stderr;                           // output to stderr by default
  env.format = CALL_GRAPH;                    // report in call-graph format by default
  env.sample_time_ns = 1000;                  // sample every 1us (1000ns) by default
  env.tids = vector_init(sizeof(int), NULL);  // set tid filter to empty
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err) {
    goto cleanup;
  } else if (!env.do_report && !env.argv[0] && !env.pid) {
    // either "--pid" or "-c/--command" should be specified
    fail("Please specify the traced program or its pid");
  }
  if (!env.func_pattern) env.func_pattern = strdup("*");  // trace all functions by default
  if (!env.lib_pattern) env.lib_pattern = strdup("*");    // trace all libcalls by default
  if (!env.nest_lib_pattern)
    env.nest_lib_pattern = strdup("");  // don't trace into any libraries by default

  printer = printer_init();

  if (env.do_report) {
    if ((env.avg_self || env.percent_self) && (env.avg_total || env.percent_total)) {
      // options xxx_self and xxx_total cannot work at the same time
      if (env.avg_self && env.percent_self)
        WARN("options avg_self and percent_self are ignored");
      else if (env.avg_self)
        WARN("option avg_self is ignored");
      else
        WARN("option percent_self is ignored");
      env.avg_self = env.percent_self = false;
    }
    struct report *report = report_init(printer);
    do_report(report);
    report_free(report);
    goto cleanup;
  }

  // ensure root permission
  if (geteuid() != 0) fail("Failed to run %s: permission denied", argv[0]);

  // register handlers for `Ctrl-C` and `kill 15`
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // save the old value of `kernel.perf_event_max_stack`
  sscanf(system_exec("sudo sysctl -n kernel.perf_event_max_stack"), "%d", &perf_event_max_stack);
  // let `bpf_get_stack()` only walk one step
  system_exec("sysctl -w kernel.perf_event_max_stack=1");

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  // set up libbpf errors and debug info callback
  libbpf_set_print(libbpf_print_fn);

  // load and verify the eBPF program
  skel = utrace_bpf__open();
  if (!skel) fail("Failed to open and load BPF skeleton");

  // set depth filter and time filter
  skel->rodata->max_depth = env.max_depth;
  skel->rodata->min_duration = env.min_duration;

  err = utrace_bpf__load(skel);
  if (err) fail("Failed to load and verify BPF skeleton");

  // set up ring buffer polling
  records = ring_buffer__new(bpf_map__fd(skel->maps.records), handle_event, NULL, NULL);
  if (!records) fail("Failed to create ring buffer");

  // save the old `rlimit`
  if (getrlimit(RLIMIT_NOFILE, &old_rlim) == -1) die("getrlimit");
  has_get_rlimit = true;
  struct rlimit rlim = {
    .rlim_cur = 1 << 20,
    .rlim_max = 1 << 20,
  };
  // maximize the number of file descriptors for uprobes
  if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) die("setrlimit");

  bpf_links = vector_init(sizeof(struct bpf_link *), NULL);
  // store local states for each thread
  thread_local = thread_local_init();

  // set pid and program name
  if (env.pid) {
    pid = env.pid;
    program = vmem_table_get_prog_name(pid);
  } else {
    program = resolve_full_path(env.argv[0]);
  }
  if (!program) fail("Cannot find the traced program");

  if (env.pid) {  // attach to a running process
    int cnt = bpf_probe_attach(skel, bpf_links, pid);
    DEBUG("Attached total %d uprobes", cnt);

    if (utrace_bpf__attach(skel) != 0) fail("Failed to attach BPF skeleton");
  } else {  // fork and exec the traced program
    size_t break_addr = get_entry_address(program);
    if (!break_addr) fail("Can not find entry address for breaking");

    pid = fork();
    if (pid < 0) {
      die("fork");
    } else if (pid == 0) {  // child process
      if (env.no_aslr) personality(ADDR_NO_RANDOMIZE);
      if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) die("perror");
      if (env.user) {  // exec the `program` as `env.user`
        struct passwd *user_info = getpwnam(env.user);
        if (!user_info) fail("Invalid username: %s", env.user);
        if (setuid(user_info->pw_uid)) die("setuid");
      }
      execv(program, env.argv);
      die("execv");
    } else {  // parent process
      struct gdb *gdb = gdb_init(pid);
      if (gdb_wait_for_signal(gdb) == -1) die("perror");

      break_addr = resolve_addr(break_addr) + vmem_table_get_prog_load_addr(pid);
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

  if (!vector_empty(bpf_links)) LOG(stderr, "Tracing...\n");
  print_split_line(printer);
  if (!env.flat) print_header(printer);

  if (env.do_record) {
    record = record_init(pid);
    record_header(record, argc, argv);
  }

  // process events
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
        if (kill(pid, 0)) break;  // check if the `pid` process is still running
      } else {
        int wstatus;
        // check non-blockingly whether the child process is still running
        pid_t ret = waitpid(pid, &wstatus, WNOHANG);
        if (ret > 0) {
          break;
        } else if (ret < 0) {
          fail("Exec %s error", program);
        }
      }
    }
  }

  print_split_line(printer);

// free resources
cleanup:
  for (unsigned long i = 0; i < ARRAY_SIZE(env.argv) && env.argv[i]; i++) free(env.argv[i]);
  free(env.func_pattern);
  free(env.lib_pattern);
  free(env.nest_lib_pattern);
  free(env.no_func_pattern);
  free(env.no_lib_pattern);
  vector_free(env.tids);
  free(program);
  record_free(record);
  printer_free(printer);

  utrace_bpf__destroy(skel);
  ring_buffer__free(records);
  if (bpf_links && !vector_empty(bpf_links)) {
    LOG(stderr, "Detaching...\n");
    for (size_t i = 0; i < vector_size(bpf_links); i++) {
      bpf_link__destroy(*((struct bpf_link **)vector_get(bpf_links, i)));
    }
  }
  vector_free(bpf_links);

  thread_local_free(thread_local);
  vmem_table_free(vmem_table);

  // restore the number of file descriptors
  if (has_get_rlimit && geteuid() == 0 && setrlimit(RLIMIT_NOFILE, &old_rlim) == -1)
    die("setrlimit");

  // restore the value of `kernel.perf_event_max_stack`
  if (perf_event_max_stack != -1) {
    char buf[64];
    sprintf(buf, "sudo sysctl kernel.perf_event_max_stack=%d 2> /dev/null", perf_event_max_stack);
    system_exec(buf);
  }
  fclose(env.out);

  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
