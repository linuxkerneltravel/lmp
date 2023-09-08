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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "elf.h"
#include "gdb.h"
#include "log.h"
#include "symbol.h"
#include "thread_local.h"
#include "vector.h"
#include "vmem.h"

#define BASE_ADDR 0x400000

enum LONGOPT {
  OPT_CPUID = 1000,
  OPT_FLAT,
  OPT_NOASLR,
  OPT_TID,
  OPT_TIMESTAMP,
};

static struct env {
  char **argv;
  int cpuid;
  int flat;
  int noaslr;
  FILE *output;
  pid_t pid;
  int tid;
  int timestamp;
} env;

const char *argp_program_version = "eBPF-utrace 0.0";
const char argp_program_doc[] =
    "\neBPF user function tracer (utrace).\n"
    "\n"
    "Examples:\n"
    "  sudo utrace -c \"$PROGRAM $ARGS\"\n"
    "  sudo utrace -p $PID\n";

static const struct argp_option opts[] = {
    {"command", 'c', "COMMAND", 0, "Command to run the program to be traced"},
    {"cpuid", OPT_CPUID, NULL, 0, "Display cpuid information"},
    {"debug", 'd', NULL, 0, "Display debug information"},
    {"flat", OPT_FLAT, NULL, 0, "Use flat output format"},
    {"no-randomize-addr", OPT_NOASLR, NULL, 0, "Disable address space layout randomization (aslr)"},
    {"output", 'o', "OUTPUT_FILE", 0, "Send trace output to file instead of stderr"},
    {"pid", 'p', "PID", 0, "PID of the program to be traced"},
    {"tid", OPT_TID, NULL, 0, "Display tid information"},
    {"timestamp", OPT_TIMESTAMP, NULL, 0, "Display timestamp information"},
    {}};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  switch (key) {
    case 'c':  // -c --command
      env.argv = (char **)malloc(sizeof(char *) * 16);
      for (int i = 0, len = strlen(arg), c = 0; i < len; i++) {
        if (arg[i] != ' ') {
          int j = i + 1;
          while (j < len && arg[j] != ' ') {
            ++j;
          }
          arg[j] = 0;
          env.argv[c] = strdup(arg + i);
          env.argv[c + 1] = NULL;
          ++c;
          arg[j] = ' ';
          i = j;
        }
      }
      break;
    case OPT_CPUID:  // --cpuid
      env.cpuid = 1;
      break;
    case 'd':  // -d --debug
      debug = 1;
      break;
    case OPT_FLAT:
      env.flat = 1;
      break;
    case 'h':  // -h --help
      argp_usage(state);
      exit(0);
    case 'o':
      env.output = fopen(arg, "w+");
      if (!env.output) {
        ERROR("Cannot write to %s\n", arg);
        argp_usage(state);
        exit(1);
      }
      break;
    case 'p':  // -p --pid
      env.pid = atoi(arg);
      if (env.pid < 0) {
        ERROR("Invalid pid: %d\n", env.pid);
        argp_usage(state);
        exit(1);
      }
      break;
    case OPT_NOASLR:  // --no-randomize-addr
      env.noaslr = 1;
      break;
    case OPT_TID:  // --tid
      env.tid = 1;
      break;
    case OPT_TIMESTAMP:  // --timestamp
      env.timestamp = 1;
      break;
    case ARGP_KEY_ARG:
      argp_usage(state);
      exit(1);
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

struct vmem_table *vmem_table;
struct thread_local *thread_local;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  if (level == LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, format, args);
}

static const char *skipped_functions[] = {
    "c_start", "_start", "__libc_csu_init", "__libc_csu_fini", "_dl_relocate_static_pie",
};

static bool skip_func(const char *func) {
  for (size_t i = 0, len = sizeof(skipped_functions) / sizeof(skipped_functions[0]); i < len; i++) {
    if (!strcmp(func, skipped_functions[i])) {
      return true;
    }
  }
  return false;
}

struct bpf_link *uprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *exe, size_t addr) {
  DEBUG("Attach uprobe to %s:%zx with pid = %d\n", exe, addr, pid);

  /* Attach tracepoint handler */
  struct bpf_link *link =
      bpf_program__attach_uprobe(skel->progs.uprobe, false /* not uretprobe */, pid, exe, addr);
  assert(link);

  return link;
}

struct bpf_link *uretprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *exe,
                                  size_t addr) {
  DEBUG("Attach uretprobe to %s:%zx with pid = %d\n", exe, addr, pid);

  /* Attach tracepoint handler */
  struct bpf_link *link =
      bpf_program__attach_uprobe(skel->progs.uretprobe, true /* not uretprobe */, pid, exe, addr);
  assert(link);

  return link;
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
  struct profile_record *r = data;

  unsigned int index = thread_local_get_index(thread_local, r->tid);
  enum FUNCSTATE state = thread_local_get_state(thread_local, index);

  if (r->ret) {
    if (state == STATE_EXEC) {
      struct profile_record *prer = thread_local_get_record(thread_local, index);
      log_trace_data(env.output, env.cpuid ? &(prer->cpu_id) : NULL, env.tid ? &(prer->tid) : NULL,
                     env.timestamp ? &(prer->timestamp) : NULL, r->duration_ns, prer->ustack_sz,
                     prer->name, r->ret, state, env.flat);
      thread_local_pop_record(thread_local, index);
    } else if (state == STATE_EXIT) {
      struct profile_record *prer = thread_local_get_record(thread_local, index);
      log_trace_data(env.output, env.cpuid ? &(r->cpu_id) : NULL, env.tid ? &(r->tid) : NULL,
                     env.timestamp ? &(r->timestamp) : NULL, r->duration_ns, r->ustack_sz,
                     prer->name, r->ret, state, env.flat);
      thread_local_pop_record(thread_local, index);
    }
    thread_local_set_state(thread_local, index, STATE_EXIT);
  } else {
    if (state == STATE_EXEC) {
      struct profile_record *prer = thread_local_get_record(thread_local, index);
      log_trace_data(env.output, env.cpuid ? &(prer->cpu_id) : NULL, env.tid ? &(prer->tid) : NULL,
                     env.timestamp ? &(prer->timestamp) : NULL, 0, prer->ustack_sz, prer->name,
                     r->ret, state, env.flat);
    }

    const struct symbol *sym = vmem_table_symbolize(vmem_table, r->ustack[0]);
    if (sym) {
      struct profile_record prer = *r;
      prer.name = sym->name;
      thread_local_push_record(thread_local, index, prer);
      thread_local_set_state(thread_local, index, STATE_EXEC);
    } else {
      // ignore
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer *records = NULL;
  struct utrace_bpf *skel;
  struct rlimit old_rlim;
  struct bpf_link *link;
  struct vector *bpf_links;
  pid_t pid;
  const char *program;
  int err;

  // Output to stderr by default
  env.output = stderr;
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err || (env.argv == NULL && !env.pid)) {
    return err;
  }

  if (geteuid() != 0) {
    ERROR("Failed to run %s: permission denied\n", argv[0]);
    return 1;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF program */
  skel = utrace_bpf__open_and_load();
  if (!skel) {
    ERROR("Failed to open and load bpf program\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  records = ring_buffer__new(bpf_map__fd(skel->maps.records), handle_event, NULL, NULL);
  if (!records) {
    err = -1;
    ERROR("Failed to create ring buffer\n");
    goto cleanup;
  }

  if (getrlimit(RLIMIT_NOFILE, &old_rlim) == -1) {
    ERROR("getrlimit error");
    exit(1);
  }
  struct rlimit rlim = {
      .rlim_cur = 1 << 20,
      .rlim_max = 1 << 20,
  };
  if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
    ERROR("setrlimit error");
    exit(1);
  }

  bpf_links = vector_init(sizeof(struct bpf_link *));

  thread_local = thread_local_init();
  if (env.pid) {
    pid = env.pid;
    vmem_table = vmem_table_init(pid);
    program = vmem_table_get_prog_name(vmem_table);
  } else {
    program = env.argv[0];
    if (access(program, F_OK) != 0) {
      char *path_env = getenv("PATH");
      if (path_env != NULL) {
        char *path_token = strtok(path_env, ":");
        while (path_token != NULL) {
          char full_path[256];
          snprintf(full_path, sizeof(full_path), "%s/%s", path_token, program);
          if (access(full_path, F_OK) == 0) {
            program = strdup(full_path);
          }
          path_token = strtok(NULL, ":");
        }
      }
    }
  }

  if (env.pid) {
    vmem_table = vmem_table_init(pid);
    for (size_t i = 0; i < vmem_table_size(vmem_table); i++) {
      const struct vmem *vmem = vmem_table_get(vmem_table, i);
      if (i > 0 && vmem_table_get(vmem_table, i - 1)->module == vmem->module) continue;
      vmem->module->symbol_table = symbol_table_init(module_get_name(vmem->module));
      if (!vmem->module->symbol_table) continue;
      for (size_t j = 0; j < symbol_table_size(vmem->module->symbol_table); j++) {
        const struct symbol *sym = symbol_table_get(vmem->module->symbol_table, j);
        if (strstr(module_get_name(vmem->module), program))
          if (!skip_func(sym->name)) {
            link = uprobe_attach(skel, pid, module_get_name(vmem->module), sym->addr);
            vector_push_back(bpf_links, &link);
            link = uretprobe_attach(skel, pid, module_get_name(vmem->module), sym->addr);
            vector_push_back(bpf_links, &link);
          }
      }
    }

    /* Attach tracepoints */
    assert(utrace_bpf__attach(skel) == 0);
  } else {
    struct elf_head elf;
    elf_head_begin(&elf, program);
    size_t break_addr = get_entry_address(&elf);
    if (break_addr >= BASE_ADDR) break_addr -= BASE_ADDR;
    elf_head_end(&elf);
    if (!break_addr) {
      exit(1);
    }

    pid = fork();
    if (pid < 0) {
      ERROR("Fork error\n");
      goto cleanup;
    } else if (pid == 0) {
      if (env.noaslr) personality(ADDR_NO_RANDOMIZE);
      ptrace(PTRACE_TRACEME, 0, 0, 0);
      execv(program, env.argv);
      ERROR("Execv %s error\n", program);
      exit(1);
    } else {
      struct gdb *gdb = gdb_init(pid);
      gdb_wait_for_signal(gdb);

      vmem_table = vmem_table_init(pid);
      break_addr += vmem_table_get_prog_st_addr(vmem_table);
      DEBUG("Break address: %zx\n", break_addr);

      gdb_enable_breakpoint(gdb, break_addr);
      gdb_continue_execution(gdb);
      gdb_wait_for_signal(gdb);

      int cnt = 0;
      vmem_table = vmem_table_init(pid);
      for (size_t i = 0; i < vmem_table_size(vmem_table); i++) {
        const struct vmem *vmem = vmem_table_get(vmem_table, i);
        if (i > 0 && vmem_table_get(vmem_table, i - 1)->module == vmem->module) continue;
        vmem->module->symbol_table = symbol_table_init(module_get_name(vmem->module));
        if (!vmem->module->symbol_table) continue;
        for (size_t j = 0; j < symbol_table_size(vmem->module->symbol_table); j++) {
          const struct symbol *sym = symbol_table_get(vmem->module->symbol_table, j);
          if (strstr(module_get_name(vmem->module), program))
            if (!skip_func(sym->name)) {
              cnt += 2;
              link = uprobe_attach(skel, pid, module_get_name(vmem->module), sym->addr);
              vector_push_back(bpf_links, &link);
              link = uretprobe_attach(skel, pid, module_get_name(vmem->module), sym->addr);
              vector_push_back(bpf_links, &link);
            }
        }
      }
      DEBUG("Attached total %d uprobes\n", cnt);

      /* Attach tracepoints */
      assert(utrace_bpf__attach(skel) == 0);

      gdb_disable_breakpoint(gdb, break_addr);
      gdb_free(gdb);
    }
  }

  LOG(stderr, "Tracing...\n");
  log_footer(stderr, env.cpuid, env.tid, env.timestamp);

  if (!env.flat) {
    log_header(env.output, env.cpuid, env.tid, env.timestamp);
  }
  /* Process events */
  while (!exiting) {
    err = ring_buffer__poll(records, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
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
  /* Clean up */
  ring_buffer__free(records);

  LOG(stderr, "Detaching...\n");
  for (size_t i = 0; i < vector_size(bpf_links); i++) {
    bpf_link__destroy(*((struct bpf_link **)vector_get(bpf_links, i)));
  }
  DEBUG("end destroy link\n");

  vector_free(bpf_links);

  utrace_bpf__destroy(skel);

  thread_local_free(thread_local);
  vmem_table_free(vmem_table);

  if (setrlimit(RLIMIT_NOFILE, &old_rlim) == -1) {
    ERROR("setrlimit error");
    exit(1);
  }

  return err < 0 ? -err : 0;
}
