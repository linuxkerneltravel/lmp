#include "bpf/eBPFStackCollector.h"
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
    if (a.v < b.v || (a.v == b.v && a.k.pid < b.k.pid))
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
    auto psid_count = bpf_object__find_map_by_name(obj, "psid_count");
    auto val_size = bpf_map__value_size(psid_count);
    auto value_fd = bpf_object__find_map_fd_by_name(obj, "psid_count");

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
        CountItem d(keys[i], count_value(vals + val_size * i));
        D->insert(std::lower_bound(D->begin(), D->end(), d), d);
    }
    delete[] keys;
    delete[] vals;
    return D;
};

StackCollector::operator std::string()
{
    std::ostringstream oss;
    oss << "Type:" << scale.Type << " Unit:" << scale.Unit << " Period:" << scale.Period << '\n';
    oss << "time:" << getLocalDateTime() << '\n';
    std::map<int32_t, std::vector<std::string>> traces;

    oss << "counts:\n";
    {
        auto D = sortedCountList();
        if (!D)
            return oss.str();
        oss << "pid\tusid\tksid\tcount\n";
        uint64_t trace[MAX_STACKS], *p;
        for (auto i : *D)
        {
            auto &id = i.k;
            auto &v = i.v;
            auto trace_fd = bpf_object__find_map_fd_by_name(obj, "stack_trace");
            oss << id.pid << '\t' << id.usid << '\t' << id.ksid << '\t' << v << '\n';
            if (id.usid > 0 && traces.find(id.usid) == traces.end())
            {
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
                        ss << "+0x" << std::hex << (addr - sym.start);
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
                    traces[id.usid].push_back(sym.name);
                }
            }
            if (id.ksid > 0 && traces.find(id.ksid) == traces.end())
            {
                bpf_map_lookup_elem(trace_fd, &id.ksid, trace);
                for (p = trace + MAX_STACKS - 1; !*p; p--)
                    ;
                for (; p >= trace; p--)
                {
                    uint64_t &addr = *p;
                    symbol sym;
                    sym.reset(addr);
                    if (g_symbol_parser.find_kernel_symbol(sym))
                        ;
                    else
                    {
                        std::stringstream ss("");
                        ss << "0x" << std::hex << addr;
                        sym.name = ss.str();
                        g_symbol_parser.putin_symbol_cache(pid, addr, sym.name);
                    }
                    clearSpace(sym.name);
                    traces[id.ksid].push_back(sym.name);
                }
            }
        }
        delete D;
    }

    oss << "traces:\n";
    {
        oss << "sid\ttrace\n";
        for (auto i : traces)
        {
            oss << i.first << "\t";
            for (auto s : i.second)
            {
                oss << s << ';';
            }
            oss << "\n";
        }
    }

    oss << "groups:\n";
    {
        auto tgid_fd = bpf_object__find_map_fd_by_name(obj, "pid_tgid");
        if (tgid_fd < 0)
        {
            return oss.str();
        }
        auto keys = new uint32_t[MAX_ENTRIES];
        auto vals = new uint32_t[MAX_ENTRIES];
        uint32_t count = MAX_ENTRIES;
        uint32_t next_key;
        int err = bpf_map_lookup_batch(tgid_fd, NULL, &next_key, keys, vals,
                                       &count, NULL);
        if (err == EFAULT)
        {
            return oss.str();
        }
        oss << "pid\ttgid\n";
        for (uint32_t i = 0; i < count; i++)
        {
            oss << keys[i] << '\t' << vals[i] << '\n';
        }
        delete[] keys;
        delete[] vals;
    }

    oss << "commands:\n";
    {
        auto comm_fd = bpf_object__find_map_fd_by_name(obj, "pid_comm");
        if (comm_fd < 0)
        {
            return oss.str();
        }
        auto keys = new uint32_t[MAX_ENTRIES];
        auto vals = new char[MAX_ENTRIES][16];
        uint32_t count = MAX_ENTRIES;
        uint32_t next_key;
        int err = bpf_map_lookup_batch(comm_fd, NULL, &next_key, keys, vals,
                                       &count, NULL);
        if (err == EFAULT)
        {
            return oss.str();
        }
        oss << "pid\tcommand\n";
        for (uint32_t i = 0; i < count; i++)
        {
            oss << keys[i] << '\t' << vals[i] << '\n';
        }
        delete[] keys;
        delete[] vals;
    }

    oss << "OK\n";
    return oss.str();
}