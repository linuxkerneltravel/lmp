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
#include <ctype.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gdb.h"
#include "log.h"
#include "symbol.h"
#include "vmap.h"

#define BASE_ADDR 0x400000  // for no-pie option

enum longopt {
  CPUID = 1000,
  NOASLR,
  TID,
  TIMESTAMP,
};

static struct env {
  char **argv;
  int cpuid;
  int noaslr;
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
    {"cpuid", CPUID, NULL, 0, "Display cpuid information"},
    {"debug", 'd', NULL, 0, "Display debug information"},
    {"no-aslr", NOASLR, NULL, 0, "Disable address space layout randomization (aslr)"},
    {"pid", 'p', "P", 0, "PID of the program to be traced"},
    {"tid", TID, NULL, 0, "Display tid information"},
    {"timestamp", TIMESTAMP, NULL, 0, "Display timestamp information"},
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
    case CPUID:  // --cpuid
      env.cpuid = 1;
      break;
    case 'd':  // -d --debug
      debug = 1;
      break;
    case 'h':  // -h --help
      argp_usage(state);
      exit(0);
    case 'p':  // -p --pid
      env.pid = atoi(arg);
      if (env.pid < 0) {
        ERROR("Invalid pid: %d\n", env.pid);
        argp_usage(state);
      }
      break;
    case NOASLR:  // --no-aslr
      env.noaslr = 1;
      break;
    case TID:  // --tid
      env.tid = 1;
      break;
    case TIMESTAMP:  // --timestamp
      env.timestamp = 1;
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

struct symbol_tab *symtab;
static struct vmap_list *vmap_list;

char buf[MAX_SYMBOL_LEN];
char stack_func[MAX_STACK_DEPTH][MAX_SYMBOL_LEN];
int status = -1, pre_ustack_sz = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  if (level == LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, format, args);
}

void uprobe_attach(struct utrace_bpf *skel, pid_t pid, const char *exe, size_t addr) {
  DEBUG("Attach to %s:%zx with pid = %d\n", exe, addr, pid);

  /* Attach tracepoint handler */
  skel->links.uprobe =
      bpf_program__attach_uprobe(skel->progs.uprobe, false /* not uretprobe */, pid, exe, addr);

  assert(skel->links.uprobe);

  skel->links.uretprobe =
      bpf_program__attach_uprobe(skel->progs.uretprobe, true /* uretprobe */, pid, exe, addr);

  assert(skel->links.uretprobe);
}

bool symbolize(size_t addr) {
  struct vmap *vmap = get_vmap(vmap_list, addr);
  if (vmap == NULL) return false;
  for (struct symbol_arr *symbols = symtab->head; symbols != NULL; symbols = symbols->next) {
    if (strcmp(symbols->libname, basename(vmap->module)) != 0) continue;
    char *name = find_symbol_name(symbols, addr - vmap->addr_st + vmap->offset);
    if (name == NULL) return false;
    memcpy(buf, name, strlen(name));
    buf[strlen(name)] = 0;
    return true;
  }
  return false;
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
  static struct profile_record pending_r;
  static int pending = 0;
  static int status = -1; /**< 0: exec 1: exit */

  const struct profile_record *r = data;

  if (r->exit) {
    // LOG("EXIT");
    // LOG(" %llx\n", r->ustack);
    // for (int i = 0; i < r->ustack_sz; i++) LOG(" %llx", r->ustack[i]);
    // LOG(" %s\n", stack_func[r->ustack_sz]);
    // return 0;
    if (status == 0) {
      if (env.cpuid) {
        log_cpuid(pending_r.cpu_id);
        log_split();
      }
      if (env.tid) {
        log_tid(pending_r.tid);
        log_split();
      }
      if (env.timestamp) {
        log_timestamp(pending_r.timestamp);
        log_split();
      }
      log_duration(r->duration_ns);
      log_split();
      log_char(' ', 2 * pending_r.ustack_sz);
      LOG("%s();\n", stack_func[pending_r.global_sz]);
    } else {  // status == 1
      if (env.cpuid) {
        log_cpuid(r->cpu_id);
        log_split();
      }
      if (env.tid) {
        log_tid(r->tid);
        log_split();
      }
      if (env.timestamp) {
        log_timestamp(r->timestamp);
        log_split();
      }
      log_duration(r->duration_ns);
      log_split();
      log_char(' ', 2 * r->ustack_sz);
      LOG("} ");
      log_color(TERM_GRAY);
      LOG("/* %s */\n", stack_func[r->global_sz]);
      log_color(TERM_NC);
    }
    pending = 0;
    status = 1;
  } else {
    // LOG("EXEC");
    // LOG(" %llx\n", r->ustack);
    // for (int i = 0; i < r->ustack_sz; i++) LOG(" %llx", r->ustack[i]);
    // if (symbolize(r->ustack[0])) {
    //    memcpy(stack_func[r->ustack_sz], buf, sizeof(buf));
    // }
    // LOG(" %s\n", stack_func[r->ustack_sz]);
    // return 0;
    if (status == 0) {
      if (env.cpuid) {
        log_cpuid(pending_r.cpu_id);
        log_split();
      }
      if (env.tid) {
        log_tid(pending_r.tid);
        log_split();
      }
      if (env.timestamp) {
        log_timestamp(pending_r.timestamp);
        log_split();
      }
      log_char(' ', 11);
      log_split();
      log_char(' ', 2 * pending_r.ustack_sz);
      LOG("%s() {\n", stack_func[pending_r.global_sz]);
    }
    if (symbolize(r->ustack)) {
      memcpy(stack_func[r->global_sz], buf, sizeof(buf));
      pending_r = *r;
      pending = 1;
      status = 0;
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer *records = NULL;
  struct utrace_bpf *skel;
  struct rlimit old_rlim;
  pid_t pid;
  const char *program;
  int err;

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

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  skel = utrace_bpf__open();
  if (!skel) {
    ERROR("Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = utrace_bpf__load(skel);
  if (err) {
    ERROR("Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  records = ring_buffer__new(bpf_map__fd(skel->maps.records), handle_event, NULL, NULL);
  if (!records) {
    err = -1;
    ERROR("Failed to create ring buffer\n");
    goto cleanup;
  }

  if (env.pid) {
    pid = env.pid;
    vmap_list = init_vmap_list(pid);
    program = get_program(vmap_list);
  } else {
    program = env.argv[0];
  }

  symtab = new_symbol_tab();
  push_symbol_arr(symtab, new_symbol_arr(program));
  for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
       sym++) {
    if (sym->addr >= BASE_ADDR) sym->addr -= BASE_ADDR;
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

  if (env.pid) {
    size_t pre_addr = 0;
    for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
         sym++) {
      if (strcmp(sym->name, "_start") == 0)
        continue;
      else if (strcmp(sym->name, "__libc_csu_init") == 0)
        continue;
      else if (strcmp(sym->name, "__libc_csu_fini") == 0)
        continue;
      else if (strcmp(sym->name, "_dl_relocate_static_pie") == 0)
        continue;
      if (sym->addr != pre_addr) {
        uprobe_attach(skel, pid, program, sym->addr);
        pre_addr = sym->addr;
      }
    }

    for (struct vmap *vmap = vmap_list->head, *prev_vmap = NULL; vmap != NULL;
         prev_vmap = vmap, vmap = vmap->next) {
      if (strcmp(basename(vmap->module), basename(program)) == 0) continue;
      if (prev_vmap != NULL && strcmp(prev_vmap->module, vmap->module) == 0) continue;
      struct symbol_arr *symbols = new_symbol_arr(vmap->module);
      if (!symbols) continue;
      push_symbol_arr(symtab, symbols);
      size_t pre_addr = 0;
      for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
           sym++) {
        if (strcmp(sym->name, "__cxa_finalize") == 0)
          continue;
        else if (strcmp(sym->name, "__libc_start_main") == 0)
          continue;
        if (sym->addr != pre_addr) {
          uprobe_attach(skel, pid, vmap->module, sym->addr);
          pre_addr = sym->addr;
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
      struct gdb *gdb = init_gdb(pid);
      wait_for_signal(gdb);

      vmap_list = init_vmap_list(pid);
      break_addr += get_prog_addr_st(vmap_list);
      DEBUG("break address: %zx\n", break_addr);

      enable_breakpoint(gdb, break_addr);
      continue_execution(gdb);
      wait_for_signal(gdb);

      size_t pre_addr = 0;
      for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
           sym++) {
        if (strcmp(sym->name, "_start") == 0)
          continue;
        else if (strcmp(sym->name, "__libc_csu_init") == 0)
          continue;
        else if (strcmp(sym->name, "__libc_csu_fini") == 0)
          continue;
        else if (strcmp(sym->name, "_dl_relocate_static_pie") == 0)
          continue;
        if (sym->addr != pre_addr) {
          uprobe_attach(skel, pid, program, sym->addr);
          pre_addr = sym->addr;
        }
      }

      for (struct vmap *vmap = vmap_list->head, *prev_vmap = NULL; vmap != NULL;
           prev_vmap = vmap, vmap = vmap->next) {
        if (strcmp(basename(vmap->module), basename(program)) == 0) continue;
        if (prev_vmap != NULL && strcmp(prev_vmap->module, vmap->module) == 0) continue;
        push_symbol_arr(symtab, new_symbol_arr(vmap->module));
        size_t pre_addr = 0;
        for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
             sym++) {
          if (strcmp(sym->name, "__cxa_finalize") == 0)
            continue;
          else if (strcmp(sym->name, "__libc_start_main") == 0)
            continue;
          if (sym->addr != pre_addr) {
            uprobe_attach(skel, pid, vmap->module, sym->addr);
            pre_addr = sym->addr;
          }
        }
      }

      /* Attach tracepoints */
      assert(utrace_bpf__attach(skel) == 0);

      disable_breakpoint(gdb, break_addr);
      free_gdb(gdb);
    }
  }
  log_header(env.cpuid, env.tid, env.timestamp);
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

cleanup:
  /* Clean up */
  ring_buffer__free(records);
  utrace_bpf__destroy(skel);

  delete_symbol_tab(symtab);
  free_vmap_list(vmap_list);

  if (setrlimit(RLIMIT_NOFILE, &old_rlim) == -1) {
    ERROR("setrlimit error");
    exit(1);
  }

  DEBUG("finish");
  return err < 0 ? -err : 0;
}