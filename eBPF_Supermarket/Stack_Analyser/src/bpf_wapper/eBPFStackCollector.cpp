// Copyright 2024 The LMP Authors.
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
// author: luiyanbing@foxmail.com
//
// 包装用于采集调用栈数据的eBPF程序，规定一些抽象接口和通用变量

#include "bpf_wapper/eBPFStackCollector.h"
#include "user.h"
#include "trace.h"

#include <sstream>
#include <map>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/version.h>
#include <cxxabi.h>

std::string getLocalDateTime(void)
{
    auto t = time(NULL);
    auto localTm = localtime(&t);
    char buff[32];
    strftime(buff, 32, "%Y%m%d_%H_%M_%S", localTm);
    return std::string(buff);
};

bool operator<(const CountItem a, const CountItem b)
{
    if (a.v[0] < b.v[0] || (a.v[0] == b.v[0] && a.k.pid < b.k.pid))
        return true;
    else
        return false;
}

StackCollector::StackCollector()
{
    self_tgid = getpid();
};

std::vector<CountItem> *StackCollector::sortedCountList(void)
{
    auto psid_count_map = bpf_object__find_map_by_name(obj, "psid_count_map");
    auto val_size = bpf_map__value_size(psid_count_map);
    auto value_fd = bpf_object__find_map_fd_by_name(obj, "psid_count_map");

    auto D = new std::vector<CountItem>();
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
    for (psid prev_key = {0}, curr_key = {0};; prev_key = curr_key)
    {
        if (bpf_map_get_next_key(value_fd, &prev_key, &curr_key))
        {
            if (errno != ENOENT)
                perror("map get next key error");
            break; // no more keys, done
        }
        if (showDelta)
            bpf_map_delete_elem(value_fd, &prev_key);
        char val[val_size];
        memset(val, 0, val_size);
        if (bpf_map_lookup_elem(value_fd, &curr_key, &val))
        {
            if (errno != ENOENT)
            {
                perror("map lookup error");
                break;
            }
            continue;
        }
        CountItem d(curr_key, count_values(val));
        D->insert(std::lower_bound(D->begin(), D->end(), d), d);
    }
#else
    auto keys = new psid[MAX_ENTRIES];
    auto vals = new char[MAX_ENTRIES * val_size];
    uint32_t count = MAX_ENTRIES;
    psid next_key;
    int err;
    if (showDelta)
        err = bpf_map_lookup_and_delete_batch(value_fd, NULL, &next_key, keys, vals, &count, NULL);
    else
        err = bpf_map_lookup_batch(value_fd, NULL, &next_key, keys, vals, &count, NULL);
    if (err == EFAULT)
        return NULL;
    for (uint32_t i = 0; i < count; i++)
    {
        CountItem d(keys[i], count_values(vals + val_size * i));
        D->insert(std::lower_bound(D->begin(), D->end(), d), d);
    }
    delete[] keys;
    delete[] vals;
#endif
    return D;
};

StackCollector::operator std::string()
{
    std::ostringstream oss;
    oss << _RED "time:" << getLocalDateTime() << _RE "\n";
    std::map<int32_t, std::vector<std::string>> traces;
    std::map<uint32_t, task_info> infos;

    oss << _BLUE "counts:" _RE "\n";
    {
        auto D = sortedCountList();
        if (!D)
            return oss.str();
        if ((*D).size() > top)
        {
            auto end = (*D).end();
            auto begin = end - top;
            for (auto i = (*D).begin(); i < begin; i++)
                delete i->v;
            (*D).assign(begin, end);
        }
        oss << _GREEN "pid\tusid\tksid";
        for (int i = 0; i < scale_num; i++)
            oss << '\t' << scales[i].Type << "/" << scales[i].Period << scales[i].Unit;
        oss << _RE "\n";
        uint64_t trace[MAX_STACKS], *p;
        for (auto &i : *D)
        {
            auto &id = i.k;
            oss << id.pid << '\t' << id.usid << '\t' << id.ksid;
            {
                auto &v = i.v;
                for (int i = 0; i < scale_num; i++)
                    oss << '\t' << v[i];
                delete v;
            }
            oss << '\n';
            auto trace_fd = bpf_object__find_map_fd_by_name(obj, "sid_trace_map");
            if (id.usid > 0 && traces.find(id.usid) == traces.end())
            {
                syms = syms_cache__get_syms(syms_cache, id.pid);
                if (!syms)
                    fprintf(stderr, "failed to get syms\n");
                else
                {
                    bpf_map_lookup_elem(trace_fd, &id.usid, trace);
                    for (p = trace + MAX_STACKS - 1; !*p; p--)
                        ;
                    std::vector<std::string> sym_trace(p - trace + 1);
                    for (int i = 0; p >= trace; p--)
                    {
                        struct sym *sym = syms__map_addr(syms, *p);
                        if (sym)
                        {
                            if (sym->name[0] == '_' && sym->name[1] == 'Z')
                            {
                                char *demangled = abi::__cxa_demangle(sym->name, NULL, NULL, NULL);
                                if (demangled)
                                {
                                    clearSpace(demangled);
                                    sym->name = demangled;
                                }
                            }
                            sym_trace[i++] = std::string(sym->name) + "+" + std::to_string(sym->offset);
                        }
                        else
                            sym_trace[i++] = "[unknown]";
                    }
                    traces[id.usid] = sym_trace;
                }
            }
            if (id.ksid > 0 && traces.find(id.ksid) == traces.end())
            {
                bpf_map_lookup_elem(trace_fd, &id.ksid, trace);
                for (p = trace + MAX_STACKS - 1; !*p; p--)
                    ;
                std::vector<std::string> sym_trace(p - trace + 1);
                for (int i = 0; p >= trace; p--)
                {
                    const struct ksym *ksym = ksyms__map_addr(ksyms, *p);
                    sym_trace[i++] = ksym ? std::string(ksym->name) + "+" + std::to_string(*p - ksym->addr)
                                          : "[unknown]";
                }
                traces[id.ksid] = sym_trace;
            }
            auto info_fd = bpf_object__find_map_fd_by_name(obj, "pid_info_map");
            task_info info;
            bpf_map_lookup_elem(info_fd, &id.pid, &info);
            infos[id.pid] = info;
        }
        delete D;
    }

    oss << _BLUE "traces:" _RE "\n";
    {
        oss << _GREEN "sid\ttrace" _RE "\n";
        for (auto i : traces)
        {
            oss << i.first << "\t";
            for (auto s : i.second)
                oss << s << ';';
            oss << "\n";
        }
    }

    oss << _BLUE "info:" _RE "\n";
    {
        oss << _GREEN "pid\tNSpid\tcomm\ttgid\tcgroup\t" _RE "\n";
        for (auto i : infos)
        {
            auto cgroup_fd = bpf_object__find_map_fd_by_name(obj, "tgid_cgroup_map");
            char group[CONTAINER_ID_LEN];
            bpf_map_lookup_elem(cgroup_fd, &(i.second.tgid), &group);
            oss << i.first << '\t'
                << i.second.pid << '\t'
                << i.second.comm << '\t'
                << i.second.tgid << '\t'
                << group << '\n';
        }
    }

    oss << _BLUE "OK" _RE "\n";
    return oss.str();
}
