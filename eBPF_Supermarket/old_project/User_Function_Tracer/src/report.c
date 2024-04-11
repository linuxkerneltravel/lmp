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
// Report the traced data in the specified format

#include "report.h"

#include <stdlib.h>
#include <string.h>

#include "env.h"
#include "glob.h"
#include "log.h"
#include "util.h"

/**
 * @brief free the malloced `name` and `libname` in each user_record
 */
static void user_record_free(void *user_record) {
  struct user_record *urecord = user_record;
  free(urecord->name);
  free(urecord->libname);
}

struct report *report_init(struct printer *printer) {
  struct report *report = malloc(sizeof(struct report));
  report->in = fopen("./utrace.data", "rb");
  if (!report->in) die("fopen");
  report->printer = printer;
  report->records = vector_init(sizeof(struct user_record), user_record_free);
  return report;
}

/**
 * @brief maintain function time for summary
 */
struct summary_info {
  unsigned long long min_total_time; /**< the minimum total time among each call */
  unsigned long long max_total_time; /**< the maximum total time among each call */
  unsigned long long sum_total_time; /**< the sum of total time of each call */
  unsigned long long min_self_time;  /**< the minimum self time among each call */
  unsigned long long max_self_time;  /**< the maximum self time among each call */
  unsigned long long sum_self_time;  /**< the sum of self time of each call */
  unsigned long long
      sub_self_time[MAX_STACK_SIZE]; /**< the sum of sub-function total time that
                                          needs to be excluded to compute self time */
  size_t calls;                      /**< function call number */
  const char *name;                  /**< function name */
  const char *libname;               /**< library name */
};

/**
 * @brief sort by function total_time in descending order
 * @param[in] lhs struct summary_info*
 * @param[in] rhs struct summary_info*
 */
static int total_time_greater(const void *lhs, const void *rhs) {
  const unsigned long long total_time1 = ((struct summary_info *)lhs)->sum_total_time;
  const unsigned long long total_time2 = ((struct summary_info *)rhs)->sum_total_time;
  return total_time1 < total_time2 ? 1 : (total_time1 > total_time2 ? -1 : 0);
}

/**
 * @brief sort by function self_time in descending order
 * @param[in] lhs struct summary_info*
 * @param[in] rhs struct summary_info*
 */
static int self_time_greater(const void *lhs, const void *rhs) {
  const unsigned long long self_time1 = ((struct summary_info *)lhs)->sum_self_time;
  const unsigned long long self_time2 = ((struct summary_info *)rhs)->sum_self_time;
  return self_time1 < self_time2 ? 1 : (self_time1 > self_time2 ? -1 : 0);
}

/**
 * @brief compare by thread ID
 * @param[in] lhs int*
 * @param[in] rhs int*
 */
static int tid_cmp(const void *lhs, const void *rhs) {
  const int tid1 = *(int *)lhs;
  const int tid2 = *(int *)rhs;
  return tid1 < tid2 ? 1 : (tid1 > tid2 ? -1 : 0);
}

/**
 * @brief analyze the traced data
 */
static void report_summary(struct report *report) {
  struct vector *tids = vector_init(sizeof(int), NULL);
  struct vector *stack = vector_init(sizeof(size_t), NULL);
  struct vector *function_infos = vector_init(sizeof(struct summary_info), NULL);

  unsigned long long all_sum_total_time = 0;
  unsigned long long all_sum_self_time = 0;
  for (size_t i = 0; i < vector_size(report->records); i++) {
    const struct user_record *curr = vector_const_get(report->records, i);
    // process each thread independently
    if (vector_find(tids, &curr->krecord.tid, tid_cmp))
      continue;  // thread `tid` has been processed

    for (size_t j = i; j < vector_size(report->records); j++) {
      const struct user_record *r = vector_const_get(report->records, j);
      if (r->krecord.tid != curr->krecord.tid)
        continue;  // only process user_record in thread `tid` now
      if (r->krecord.ret) {
        // update the corresponding function_info, which is guaranteed to exist
        struct summary_info *info;
        for (size_t index = 0; index < vector_size(function_infos); index++) {
          info = vector_get(function_infos, index);
          if (!strcmp(info->name, r->name) && !strcmp(info->libname, r->libname)) break;
        }
        // update sum total time
        info->sum_total_time += r->duration_ns;
        // update min total time
        if (!info->min_total_time)
          info->min_total_time = r->duration_ns;
        else if (r->duration_ns < info->min_total_time)
          info->min_total_time = r->duration_ns;
        // update max total time
        if (r->duration_ns > info->max_total_time) info->max_total_time = r->duration_ns;
        all_sum_total_time += r->duration_ns;

        unsigned long long cur_self_time =
            r->duration_ns -
            info->sub_self_time[r->krecord.ustack_sz];  // exclude sub functions' time
        info->sub_self_time[r->krecord.ustack_sz] = 0;
        // update sum self time
        info->sum_self_time += cur_self_time;
        // update min self time
        if (!info->min_self_time)
          info->min_self_time = cur_self_time;
        else if (cur_self_time < info->min_self_time)
          info->min_self_time = cur_self_time;
        // update max self time
        if (cur_self_time > info->max_self_time) info->max_self_time = cur_self_time;
        all_sum_self_time += cur_self_time;
        info->calls++;

        vector_pop_back(stack);
        if (!vector_empty(stack)) {
          // remove the time used by sub-functions, e.g., if f() calls g(), self_time(f()) should
          // exclude total_time(g())
          const struct user_record *prer =
              vector_const_get(report->records, *(size_t *)vector_back(stack));
          for (size_t k = vector_size(function_infos); k > 0; k--) {
            struct summary_info *pre_info = vector_get(function_infos, k - 1);
            if (!strcmp(pre_info->name, prer->name) && !strcmp(pre_info->libname, prer->libname)) {
              pre_info->sub_self_time[prer->krecord.ustack_sz] += r->duration_ns;
              break;
            }
          }
        }
      } else {
        // if the corresponding function_info does not exist, create it
        size_t index = 0;
        for (; index < vector_size(function_infos); index++) {
          const struct summary_info *info = vector_const_get(function_infos, index);
          if (!strcmp(info->name, r->name) && !strcmp(info->libname, r->libname)) break;
        }
        if (index == vector_size(function_infos)) {
          struct summary_info info;
          info.sum_total_time = info.min_total_time = info.max_total_time = 0;
          info.sum_self_time = info.min_self_time = info.max_self_time = 0;
          memset(info.sub_self_time, 0, sizeof(info.sub_self_time));
          info.calls = 0;
          info.name = r->name;
          info.libname = r->libname;
          vector_push_back(function_infos, &info);
        }
        vector_push_back(stack, &j);
      }
    }

    vector_push_back(tids, &curr->krecord.tid);
  }
  (env.avg_self || env.percent_self) ? vector_sort(function_infos, self_time_greater)
                                     : vector_sort(function_infos, total_time_greater);

  int width = 60;
  if (env.percent_total || env.percent_self) {
    LOG(report->printer->out, "  PERCENT  |");
    width += 12;
  }
  if (env.avg_total || env.percent_total) {
    if (env.avg_total) {
      LOG(report->printer->out, "  TOTAL AVG  |  TOTAL MIN  |  TOTAL MAX  |");
      width += 42;
    }
    LOG(report->printer->out, "  TOTAL TIME  |  CALLS  |  FUNCTION\n");
  } else if (env.avg_self || env.percent_self) {
    if (env.avg_self) {
      LOG(report->printer->out, "   SELF AVG  |   SELF MIN  |  SELF MAX  |");
      width += 42;
    }
    LOG(report->printer->out, "   SELF TIME  |  CALLS  |  FUNCTION\n");
  } else {
    LOG(report->printer->out, "  TOTAL TIME  |  SELF TIME  |  CALLS  |  FUNCTION\n");
  }
  print_chars(report->printer, '=', width);
  print_chars(report->printer, '\n', 1);
  for (size_t i = 0; i < vector_size(function_infos); i++) {
    const struct summary_info *info = vector_const_get(function_infos, i);
    if (env.percent_total) {
      unsigned long long percent_x = info->sum_total_time * 100 / all_sum_total_time;
      unsigned long long percent_y = (info->sum_total_time * 100 - percent_x * all_sum_total_time) *
                                     100 / all_sum_total_time % 100;
      LOG(report->printer->out, "   %2llu.%02llu%%   ", percent_x, percent_y);
    }
    if (env.percent_self) {
      unsigned long long percent_x = info->sum_self_time * 100 / all_sum_self_time;
      unsigned long long percent_y = (info->sum_self_time * 100 - percent_x * all_sum_self_time) *
                                     100 / all_sum_self_time % 100;
      LOG(report->printer->out, "   %2llu.%02llu%%   ", percent_x, percent_y);
    }
    if (env.avg_total) {
      print_chars(report->printer, ' ', 1);
      print_duration(report->printer, info->sum_total_time / info->calls, true, true, false);
      print_chars(report->printer, ' ', 3);
      print_duration(report->printer, info->min_total_time, true, true, false);
      print_chars(report->printer, ' ', 3);
      print_duration(report->printer, info->max_total_time, true, true, false);
      print_chars(report->printer, ' ', 2);
    }
    if (env.avg_self) {
      print_chars(report->printer, ' ', 1);
      print_duration(report->printer, info->sum_self_time / info->calls, true, true, false);
      print_chars(report->printer, ' ', 3);
      print_duration(report->printer, info->min_self_time, true, true, false);
      print_chars(report->printer, ' ', 3);
      print_duration(report->printer, info->max_self_time, true, true, false);
      print_chars(report->printer, ' ', 2);
    }
    if (!(env.avg_self || env.percent_self)) {  // when not specifying "--avg-self" or
                                                // "--percent_self", show TOTAL TIME
      print_chars(report->printer, ' ', 2);
      // need_blank = true, need_color = true, need_sign = false
      print_duration(report->printer, info->sum_total_time, true, true, false);
      print_chars(report->printer, ' ', 1);
    }
    if (!(env.avg_total || env.percent_total)) {  // when specifying "--avg-total" or
                                                  // "--percent_total", show SELF TIME
      print_chars(report->printer, ' ', 2);
      // need_blank = true, need_color = true, need_sign = false
      print_duration(report->printer, info->sum_self_time, true, true, false);
      print_chars(report->printer, ' ', 1);
    }
    print_chars(report->printer, ' ', 2);
    LOG(report->printer->out, "%6zu      %s\n", info->calls, info->name);
  }
  print_chars(report->printer, '=', width);
  print_chars(report->printer, '\n', 1);

  vector_free(tids);
  vector_free(stack);
  vector_free(function_infos);
}

/**
 * @brief report the traced data in chrome tracing format
 */
static void report_chrome(struct report *report) {
  LOG(report->printer->out, "{\"traceEvents\":[\n");
  for (size_t i = 0; i < vector_size(report->records); i++) {
    const struct user_record *r = vector_const_get(report->records, i);
    LOG(report->printer->out, "{");
    LOG(report->printer->out, "\"ts\":%llu.%03llu,", r->krecord.timestamp / 1000,
        r->krecord.timestamp % 1000);
    LOG(report->printer->out, "\"ph\":");
    if (r->krecord.ret)
      LOG(report->printer->out, "\"E\",");
    else
      LOG(report->printer->out, "\"B\",");
    LOG(report->printer->out, "\"pid\":%u,", report->pid);
    if (r->krecord.tid != report->pid) LOG(report->printer->out, "\"tid\":%u,", r->krecord.tid);
    LOG(report->printer->out, "\"name\":\"%s\"", r->name);
    LOG(report->printer->out, "}");
    if (i + 1 < vector_size(report->records))
      LOG(report->printer->out, ",\n");
    else
      LOG(report->printer->out, "],\n");
  }
  LOG(report->printer->out, "\"displayTimeUnit\":\"ns\",\"metadata\":{\n");
  LOG(report->printer->out, "\"recorded_time\":\"%s\",\n", report->trace_time);
  LOG(report->printer->out, "\"command_line\":\"%s\"}}\n", report->cmdline);
}

/**
 * @brief maintain folded stack counts
 */
struct flame_graph_info {
  char *stack;                /**< function stack, concated by ';' */
  int tid;                    /**< thread ID */
  unsigned long long samples; /**< sample count */
};

/**
 * @brief free the malloced `stack` in each flmae_graph_info
 */
void flame_graph_info_free(void *flame_graph_info) {
  struct flame_graph_info *info = flame_graph_info;
  free(info->stack);
}

/**
 * @brief sort by `strlen(stack)` in ascending order
 * @param[in] lhs struct flame_graph_info*
 * @param[in] rhs struct flame_graph_info*
 */
static int stack_len_less(const void *lhs, const void *rhs) {
  const size_t len1 = strlen(((struct flame_graph_info *)lhs)->stack);
  const size_t len2 = strlen(((struct flame_graph_info *)rhs)->stack);
  return len1 < len2 ? -1 : (len1 > len2 ? 1 : 0);
}

/**
 * @brief report the traced data for generating flame graph by ""brendangregg/FlameGraph""
 */
static void report_flame_graph(struct report *report) {
  struct vector *tids = vector_init(sizeof(int), NULL);
  struct vector *stackcollapse =
      vector_init(sizeof(struct flame_graph_info), flame_graph_info_free);

  char buf[4096];
  for (size_t i = 0; i < vector_size(report->records); i++) {
    const struct user_record *curr = vector_const_get(report->records, i);
    // process each thread independently
    if (vector_find(tids, &curr->krecord.tid, tid_cmp))
      continue;  // thread `tid` has been processed

    size_t len = 0;
    for (size_t j = i; j < vector_size(report->records); j++) {
      const struct user_record *r = vector_const_get(report->records, j);
      if (r->krecord.tid != curr->krecord.tid)
        continue;  // only process user_record in thread `tid` now
      if (r->krecord.ret) {
        // update the flame_graph_info corresponding to the current stack in stackcollapse
        size_t index = vector_size(stackcollapse);
        for (; index > 0; --index) {
          const struct flame_graph_info *info = vector_const_get(stackcollapse, index - 1);
          if (!strcmp(info->stack, buf)) break;
        }
        if (!index) {
          struct flame_graph_info info;
          info.stack = strdup(buf);
          info.tid = r->krecord.tid;
          info.samples = 0;
          vector_push_back(stackcollapse, &info);
          index = vector_size(stackcollapse) - 1;
        } else {
          --index;
        }
        struct flame_graph_info *info = vector_get(stackcollapse, index);
        info->samples += r->duration_ns / env.sample_time_ns;
        len -= strlen(r->name);
        if (len > 0) buf[--len] = '\0';  // overwrite the ';'
      } else {
        if (len > 0) buf[len++] = ';';  // use ';' to join each function
        strcpy(buf + len, r->name);
        len += strlen(r->name);
      }
    }

    vector_push_back(tids, &curr->krecord.tid);
  }

  vector_sort(stackcollapse, stack_len_less);
  // remove inclusive samples, i.e. (f).samples should exclude (f;g).samples
  for (size_t i = vector_size(stackcollapse); i > 0; i--) {
    struct flame_graph_info *info1 = vector_get(stackcollapse, i - 1);
    unsigned long long inclusive_samples = 0;
    for (size_t j = i + 1; j < vector_size(stackcollapse); j++) {
      const struct flame_graph_info *info2 = vector_const_get(stackcollapse, j);
      if (info1->tid != info2->tid) continue;
      // check info1->stack is contained by info2->stack
      char *s1 = info1->stack, *s2 = info2->stack;
      while (*s1 != '\0') {
        if (*s1 != *s2) break;
        ++s1, ++s2;
      }
      if (*s1 == '\0' && *s2 == ';') inclusive_samples += info2->samples;
    }
    if (inclusive_samples < info1->samples)
      info1->samples -= inclusive_samples;
    else
      info1->samples = 0;
  }
  for (size_t i = 0; i < vector_size(stackcollapse); i++) {
    const struct flame_graph_info *info = vector_const_get(stackcollapse, i);
    if (info->samples > 0) LOG(report->printer->out, "%s %llu\n", info->stack, info->samples);
  }

  vector_free(tids);
  vector_free(stackcollapse);
}

/**
 * @brief report the traced data in the default function call graph format
 */
static void report_call_graph(struct report *report) {
  if (!env.flat) print_header(report->printer);
  struct thread_local *thread_local =
      thread_local_init();  // print_trace() needs to store info per thread
  for (size_t i = 0; i < vector_size(report->records); i++) {
    const struct user_record *r = vector_const_get(report->records, i);
    print_trace(report->printer, NULL, thread_local, NULL, r);
  }
  thread_local_free(thread_local);
}

/**
 * @brief sort by timestamp in ascending order
 * @param[in] lhs struct user_record*
 * @param[in] rhs struct user_record*
 */
static int timestamp_less(const void *lhs, const void *rhs) {
  const unsigned long long timstamp1 = ((struct user_record *)lhs)->krecord.timestamp;
  const unsigned long long timstamp2 = ((struct user_record *)rhs)->krecord.timestamp;
  return timstamp1 < timstamp2 ? -1 : (timstamp1 > timstamp2 ? 1 : 0);
}

/**
 * @brief read a string from file
 * @param[in] fp point to the file to be read
 * @return a malloced string
 * @details len (size_t) + str (const char *[])
 */
static char *read_str(FILE *fp) {
  size_t len;
  fread(&len, sizeof(size_t), 1, fp);
  char *buf = malloc(sizeof(char) * (len + 1));
  fread(buf, sizeof(char), len, fp);
  buf[len] = '\0';
  return buf;
}

void do_report(struct report *report) {
  // first read the recored header
  report->trace_time = read_str(report->in);
  report->cmdline = read_str(report->in);
  report->pid = fread(&report->pid, sizeof(report->pid), 1, report->in);
  // then read each trace entry
  struct user_record r;
  while (true) {
    if (!fread(&r.krecord.tid, sizeof(r.krecord.tid), 1, report->in)) break;
    fread(&r.krecord.timestamp, sizeof(r.krecord.timestamp), 1, report->in);
    r.name = read_str(report->in);
    r.libname = read_str(report->in);
    fread(&r.krecord.ret, sizeof(r.krecord.ret), 1, report->in);
    vector_push_back(report->records, &r);
  }

  struct vector *tids = vector_init(sizeof(int), NULL);
  struct vector *pending_records = vector_init(sizeof(struct user_record), NULL);
  struct vector *filtered_records = vector_init(sizeof(struct user_record), NULL);
  // filter records through various filters, e.g., "--tid-filter", "-f/--function", "--max-depth"
  // at the same time, we can compute `krecord.ustack_sz` and `duration_ns` for each entry
  for (size_t i = 0; i < vector_size(report->records); i++) {
    const struct user_record *curr = vector_const_get(report->records, i);
    if (!vector_empty(env.tids) && !vector_find(env.tids, &curr->krecord.tid, tid_cmp)) continue;
    // process each thread independently
    if (vector_find(tids, &curr->krecord.tid, tid_cmp))
      continue;  // thread `tid` has been processed

    unsigned int ustack_sz = 0;
    for (size_t j = i; j < vector_size(report->records); j++) {
      struct user_record *r = vector_get(report->records, j);
      if (r->krecord.tid != curr->krecord.tid)
        continue;            // only process user_record in thread `tid` now
      if (r->krecord.ret) {  // exit a function
        if (ustack_sz - 1 > env.max_depth) continue;  // filterd by max stack depth
        if (!vector_empty(pending_records)) {
          struct user_record *prer = vector_back(pending_records);
          if (!strcmp(prer->name, r->name) && !strcmp(prer->libname, r->libname)) {
            r->krecord.ustack_sz = (ustack_sz--) - 1;
            r->duration_ns = r->krecord.timestamp - prer->krecord.timestamp;
            if (r->duration_ns >= env.min_duration) {  // pass time-filter
              vector_push_back(filtered_records, prer);
              vector_push_back(filtered_records, r);
              vector_pop_back(pending_records);
            }
          }
        } else {
          // filtered
        }
      } else {                                        // enter a function
        if (ustack_sz + 1 > env.max_depth) continue;  // filterd by max stack depth
        if (!glob_match_ext(r->name, env.func_pattern) ||
            (env.no_func_pattern &&
             glob_match_ext(r->name, env.no_func_pattern)))  // filterd by function name
          continue;
        if (!glob_match_ext(r->libname, env.lib_pattern) ||
            (env.no_lib_pattern &&
             glob_match_ext(r->libname, env.no_lib_pattern)))  // filterd by library name
          continue;
        r->krecord.ustack_sz = (++ustack_sz) - 1;
        r->duration_ns = 0;
        vector_push_back(pending_records, r);
      }
    }

    vector_push_back(tids, &curr->krecord.tid);
  }
  vector_free(tids);
  vector_free(pending_records);
  struct vector *tmp = report->records;
  report->records = filtered_records;
  // since we process each thread independently, the order may be confused
  vector_sort(report->records, timestamp_less);

  if (env.format == SUMMARY) {
    report_summary(report);
  } else if (env.format == CHROME) {
    report_chrome(report);
  } else if (env.format == FLAME_GRAPH) {
    report_flame_graph(report);
  } else {
    report_call_graph(report);
  }

  report->records = tmp;
  vector_free(filtered_records);
}

void report_free(struct report *report) {
  if (report) {
    fclose(report->in);
    free(report->trace_time);
    free(report->cmdline);
    vector_free(report->records);
    free(report);
  }
}
