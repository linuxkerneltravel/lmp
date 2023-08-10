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

#include <getopt.h>

#include "utrace.h"
#include "utrace.skel.h"

#include <assert.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gdb.h"
#include "log.h"
#include "symbol.h"
#include "vmap.h"

static const struct option longopts[] = {{"command", required_argument, NULL, 'c'},
                                         {"pid", required_argument, NULL, 'p'},
                                         {"help", no_argument, NULL, 'h'},
                                         {"debug", no_argument, NULL, 'd'},
                                         {NULL, 0, NULL, 0}};

static const char *optstring = "c:p:hd";

struct args {
  pid_t pid;
  char **argv;
};

void print_usage(char *program) {
  LOG("Usage: %s [$OPTIONS...]\n", program);
  LOG("\n");
  LOG("Options:\n");
  LOG("  -c --command: the command to run the program to be traced.\n");
  LOG("  -p --pid: the PID of the program to be traced.\n");
  LOG("  -d --debug: enable debug mode.\n");
  LOG("  -h --help: disaply this usage information.\n");
  LOG("\n");
  LOG("Examples:\n");
  LOG("  %s -c \"$PROGRAM $ARGS\"\n", program);
  LOG("  %s -p $PID\n", program);
}

void parse_args(int argc, char *argv[], struct args *arg) {
  int len, c = 0;

  arg->pid = 0;
  arg->argv = (char **)malloc(sizeof(char *) * 16);

  debug = 0;

  int opt, opt_index = 1;
  while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
    switch ((char)opt) {
      case 'c':  // -c --command
        len = strlen(optarg);
        for (int i = 0; i < len; i++) {
          if (optarg[i] != ' ') {
            int j = i + 1;
            while (j < len && optarg[j] != ' ') {
              ++j;
            }
            optarg[j] = 0;
            arg->argv[c] = strdup(optarg + i);
            ++c;
            optarg[j] = ' ';
            i = j;
          }
        }
        arg->argv[c] = NULL;
        opt_index += 2;
        break;
      case 'p':  // -p --pid
        arg->pid = atoi(optarg);
        opt_index += 2;
        break;
      case 'd':  // -d --debug
        debug = 1;
        opt_index += 1;
        break;
      case 'h':  // -h --help
        print_usage(argv[0]);
        exit(0);
      default:
        print_usage(argv[0]);
        exit(1);
    }
  }

  if (!c) {
    print_usage(argv[0]);
    exit(1);
  }
}

struct symbol_tab *symtab;
struct dyn_symbol_set *dyn_symset;
struct vmap_list *vmaps;

char buf[256];
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
  struct vmap *vmap = find_vmap(vmaps, addr);
  if (vmap == NULL) return false;
  for (struct symbol_arr *symbols = symtab->head; symbols != NULL; symbols = symbols->next) {
    if (strcmp(symbols->libname, basename(vmap->libname)) != 0) continue;
    char *name = find_symbol_name(symbols, addr - vmap->addr_st + vmap->offset);
    if (name == NULL) return false;
    memcpy(buf, name, strlen(name));
    buf[strlen(name)] = 0;
    free(name);
    return true;
  }
  return false;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct profile_record *r = data;

  if (r->exit) {
    // LOG("EXIT");
    // for (int i = 0; i < r->ustack_sz; i++) LOG(" %llx", r->ustack[i]);
    // LOG(" %s\n", stack_func[r->ustack_sz]);
    // return 0;
    if (status == 0 && r->ustack_sz == pre_ustack_sz) {
      log_cpuid(r->cpu_id);
      LOG(" | ");
      log_tid(r->tid);
      LOG(" | ");
      log_time(r->duration_ns);
      LOG(" | ");
      log_char(' ', 2 * r->ustack_sz - 2);
      LOG("%s();\n", stack_func[r->ustack_sz]);
      status = 1;
      pre_ustack_sz = r->ustack_sz;
    } else if (status == 1 && r->ustack_sz == pre_ustack_sz - 1) {
      log_cpuid(r->cpu_id);
      LOG(" | ");
      log_tid(r->tid);
      LOG(" | ");
      log_time(r->duration_ns);
      LOG(" | ");
      log_char(' ', 2 * r->ustack_sz - 2);
      LOG("} /* %s */\n", stack_func[r->ustack_sz]);
      status = 1;
      pre_ustack_sz = r->ustack_sz;
    }
  } else {
    // LOG("EXEC");
    // for (int i = 0; i < r->ustack_sz; i++) LOG(" %llx", r->ustack[i]);
    // if (symbolize(r->ustack[0])) {
    //   memcpy(stack_func[r->ustack_sz], buf, sizeof(buf));
    // }
    // LOG(" %s\n", stack_func[r->ustack_sz]);
    // return 0;
    if (status == -1 && r->ustack_sz != 1) return 0;
    if (status == 0 && r->ustack_sz != pre_ustack_sz + 1) return 0;
    if (status == 1 && r->ustack_sz != pre_ustack_sz) return 0;
    if (status == 0) {
      log_cpuid(r->cpu_id);
      LOG(" | ");
      log_tid(r->tid);
      LOG(" |");
      log_char(' ', 12);
      LOG(" | ");
      log_char(' ', 2 * r->ustack_sz - 4);
      LOG("%s() {\n", stack_func[r->ustack_sz - 1]);
    }
    if (symbolize(r->ustack[0])) {
      memcpy(stack_func[r->ustack_sz], buf, sizeof(buf));
      status = 0;
      pre_ustack_sz = r->ustack_sz;
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer *records = NULL;
  struct utrace_bpf *skel;
  struct args arg;
  pid_t pid;
  char *program;
  int err;

  parse_args(argc, argv, &arg);

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

  if (arg.pid) {
    pid = arg.pid;
    program = get_program(pid);

    symtab = new_symbol_tab();
    dyn_symset = new_dyn_symbol_set();
    push_symbol_arr(symtab, new_symbol_arr(program, dyn_symset, 0));
    for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
         sym++) {
      if (strcmp(sym->name, "_start") == 0)
        continue;
      else if (strcmp(sym->name, "__libc_csu_init") == 0)
        continue;
      else if (strcmp(sym->name, "__libc_csu_fini") == 0)
        continue;
      else
        uprobe_attach(skel, pid, program, sym->addr);
    }

    vmaps = new_vmap_list(pid);
    for (struct vmap *vmap = vmaps->head, *prev_vmap = NULL; vmap != NULL;
         prev_vmap = vmap, vmap = vmap->next) {
      if (strcmp(basename(vmap->libname), basename(program)) == 0) continue;
      if (prev_vmap != NULL && strcmp(prev_vmap->libname, vmap->libname) == 0) continue;
      push_symbol_arr(symtab, new_symbol_arr(vmap->libname, dyn_symset, 1));
      for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
           sym++) {
        if (strcmp(sym->name, "__cxa_finalize") == 0)
          continue;
        else if (strcmp(sym->name, "__libc_start_main") == 0)
          continue;
        uprobe_attach(skel, pid, vmap->libname, sym->addr);
      }

      /* Attach tracepoints */
      assert(utrace_bpf__attach(skel) == 0);
    }
  } else {
    program = strdup(arg.argv[0]);

    symtab = new_symbol_tab();
    dyn_symset = new_dyn_symbol_set();
    size_t break_addr = 0;
    push_symbol_arr(symtab, new_symbol_arr(program, dyn_symset, 0));
    for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
         sym++) {
      if (strcmp(sym->name, "_start") == 0) {
        break_addr = sym->addr;
        break;
      }
    }

    pid = fork();
    if (pid < 0) {
      ERROR("Fork error\n");
      goto cleanup;
    } else if (pid == 0) {
      ptrace(PTRACE_TRACEME, 0, 0, 0);
      execv(program, arg.argv);
      ERROR("Execv %s error\n", program);
      exit(1);
    } else {
      struct gdb *gdb = new_gdb();
      wait_for_signal(pid);

      break_addr += get_base_addr(pid);
      DEBUG("break address: %zx\n", break_addr);

      enable_breakpoint(gdb, pid, break_addr);
      continue_execution(pid);
      wait_for_signal(pid);

      for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
           sym++) {
        if (strcmp(sym->name, "_start") == 0)
          continue;
        else if (strcmp(sym->name, "__libc_csu_init") == 0)
          continue;
        else if (strcmp(sym->name, "__libc_csu_fini") == 0)
          continue;
        else
          uprobe_attach(skel, pid, program, sym->addr);
      }

      vmaps = new_vmap_list(pid);
      for (struct vmap *vmap = vmaps->head, *prev_vmap = NULL; vmap != NULL;
           prev_vmap = vmap, vmap = vmap->next) {
        if (strcmp(basename(vmap->libname), basename(program)) == 0) continue;
        if (prev_vmap != NULL && strcmp(prev_vmap->libname, vmap->libname) == 0) continue;
        push_symbol_arr(symtab, new_symbol_arr(vmap->libname, dyn_symset, 1));
        for (struct symbol *sym = symtab->head->sym; sym != symtab->head->sym + symtab->head->size;
             sym++) {
          if (strcmp(sym->name, "__cxa_finalize") == 0)
            continue;
          else if (strcmp(sym->name, "__libc_start_main") == 0)
            continue;
          uprobe_attach(skel, pid, vmap->libname, sym->addr);
        }
      }

      /* Attach tracepoints */
      assert(utrace_bpf__attach(skel) == 0);

      disable_breakpoint(gdb, pid, break_addr);
      continue_execution(pid);
    }
  }

  log_header();
  /* Process events */
  while (true) {
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
      if (arg.pid) {
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
  delete_dyn_symbol_set(dyn_symset);
  delete_vmap_list(vmaps);

  return err < 0 ? -err : 0;
}