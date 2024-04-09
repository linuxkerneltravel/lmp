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
#include "sa_user.h"
#include "dt_symbol.h"

#include <sstream>
#include <map>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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
    self_pid = getpid();
};

std::vector<CountItem> *StackCollector::sortedCountList(void)
{
    auto psid_count_map = bpf_object__find_map_by_name(obj, "psid_count_map");
    auto val_size = bpf_map__value_size(psid_count_map);
    auto value_fd = bpf_object__find_map_fd_by_name(obj, "psid_count_map");

    auto keys = new psid[MAX_ENTRIES];
    auto vals = new char[MAX_ENTRIES * val_size];
    uint32_t count = MAX_ENTRIES;
    psid next_key;
    int err;
    if (showDelta)
    {
        err = bpf_map_lookup_and_delete_batch(value_fd, NULL, &next_key, keys, vals, &count, NULL);
    }
    else
    {
        err = bpf_map_lookup_batch(value_fd, NULL, &next_key, keys, vals, &count, NULL);
    }
    if (err == EFAULT)
    {
        return NULL;
    }

    auto D = new std::vector<CountItem>();
    for (uint32_t i = 0; i < count; i++)
    {
        CountItem d(keys[i], count_values(vals + val_size * i));
        D->insert(std::lower_bound(D->begin(), D->end(), d), d);
    }
    delete[] keys;
    delete[] vals;
    return D;
};

StackCollector::operator std::string()
{
    std::ostringstream oss;
    oss << _RED "time:" << getLocalDateTime() << _RE "\n";
    std::map<int32_t, std::vector<std::string>> traces;

    oss << _BLUE "counts:" _RE "\n";
    {
        auto D = sortedCountList();
        if (!D)
            return oss.str();
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
                std::vector<std::string> sym_trace;
                bpf_map_lookup_elem(trace_fd, &id.usid, trace);
                for (p = trace + MAX_STACKS - 1; !*p; p--)
                    ;
                for (; p >= trace; p--)
                {
                    uint64_t &addr = *p;
                    symbol sym;
                    sym.reset(addr);
                    elf_file file;
                    if (g_symbol_parser.find_symbol_in_cache(id.pid, addr, sym.name))
                        ;
                    else if (g_symbol_parser.get_symbol_info(id.pid, sym, file) && g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid))
                    {
                        if (sym.name[0] == '_' && sym.name[1] == 'Z')
                        // 代表是C++符号，则调用demangle解析
                        {
                            sym.name = demangleCppSym(sym.name);
                        }
                        std::stringstream ss("");
                        ss << "+0x" << std::hex << (sym.ip - sym.start);
                        sym.name += ss.str();
                        g_symbol_parser.putin_symbol_cache(id.pid, addr, sym.name);
                    }
                    else
                    {
                        std::stringstream ss("");
                        ss << "0x" << std::hex << addr;
                        sym.name = ss.str();
                        g_symbol_parser.putin_symbol_cache(id.pid, addr, sym.name);
                    }
                    clearSpace(sym.name);
                    sym_trace.push_back(sym.name);
                }
                traces[id.usid] = sym_trace;
            }
            if (id.ksid > 0 && traces.find(id.ksid) == traces.end())
            {
                std::vector<std::string> sym_trace;
                bpf_map_lookup_elem(trace_fd, &id.ksid, trace);
                for (p = trace + MAX_STACKS - 1; !*p; p--)
                    ;
                for (; p >= trace; p--)
                {
                    uint64_t &addr = *p;
                    symbol sym;
                    sym.reset(addr);
                    if (g_symbol_parser.find_kernel_symbol(sym))
		    {
                        std::stringstream ss("");
                        ss << "+0x" << std::hex << (sym.ip - sym.start);
                        sym.name += ss.str();
		    }
                    else
                    {
                        std::stringstream ss("");
                        ss << "0x" << std::hex << addr;
                        sym.name = ss.str();
                        g_symbol_parser.putin_symbol_cache(pid, addr, sym.name);
                    }
                    clearSpace(sym.name);
                    sym_trace.push_back(sym.name);
                }
                traces[id.ksid] = sym_trace;
            }
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
        auto info_fd = bpf_object__find_map_fd_by_name(obj, "pid_info_map");
        if (info_fd < 0)
        {
            return oss.str();
        }
        auto keys = new uint32_t[MAX_ENTRIES];
        auto vals = new task_info[MAX_ENTRIES];
        uint32_t count = MAX_ENTRIES;
        uint32_t next_key;
        {
            int err;
            if (showDelta)
                err = bpf_map_lookup_and_delete_batch(info_fd, NULL, &next_key,
                                                      keys, vals, &count, NULL);
            else
                err = bpf_map_lookup_batch(info_fd, NULL, &next_key,
                                           keys, vals, &count, NULL);
            if (err == EFAULT)
                return oss.str();
        }
        oss << _GREEN "pid\tNSpid\tcomm\ttgid\tcgroup" _RE "\n";
        for (uint32_t i = 0; i < count; i++)
            oss << keys[i] << '\t'
                << vals[i].pid << '\t'
                << vals[i].comm << '\t'
                << vals[i].tgid << '\t'
                << vals[i].cid << '\n';
        delete[] keys;
        delete[] vals;
    }

    oss << _BLUE "OK" _RE "\n";
    return oss.str();
}
