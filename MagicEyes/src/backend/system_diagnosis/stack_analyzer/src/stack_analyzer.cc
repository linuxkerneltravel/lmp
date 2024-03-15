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
// author: luiyanbing@foxmail.com
//
// 用户态bpf的主程序代码，主要用于数据的显示和整理

#include <map>
#include <vector>
#include <sstream>
#include <iostream>
#include <cxxabi.h>
#include <string>

#include "stack_analyzer/include/symbol.h"
#include "stack_analyzer/include/clipp.h"

extern "C"
{
#include <linux/perf_event.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/wait.h>

#include "stack_analyzer/include/sa_user.h"
#include "system_diagnosis/stack_analyzer/on_cpu_count.skel.h"
#include "system_diagnosis/stack_analyzer/off_cpu_count.skel.h"
#include "system_diagnosis/stack_analyzer/mem_count.skel.h"
#include "system_diagnosis/stack_analyzer/io_count.skel.h"
#include "system_diagnosis/stack_analyzer/pre_count.skel.h"
#include "system_diagnosis/stack_analyzer/stack_count.skel.h"
}

void splitString(std::string symbol, const char split, std::vector<std::string> &res)
{
    if (symbol == "")
        return;
    std::string strs = symbol + split;
    size_t pos = strs.find(split);
    while (pos != strs.npos)
    {
        std::string temp = strs.substr(0, pos);
        res.push_back(temp);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(split);
    }
}

std::string getLocalDateTime(void)
{
    auto t = time(NULL);
    auto localTm = localtime(&t);
    char buff[32];
    strftime(buff, 32, "%Y%m%d_%H_%M_%S", localTm);
    return std::string(buff);
}

// 模板用来统一调用多个类有同样但未被抽象的接口
// 虚函数用来规范接口来被统一调用

class StackCollector
{
private:
    /// @brief count类，主要是为了重载比较运算，便于自动排序
    class CountItem
    {
    public:
        uint32_t pid;
        int32_t ksid, usid;
        double val;
        CountItem(int32_t p, int32_t k, int32_t u, double v)
        {

            pid = p;
            ksid = k;
            usid = u;
            val = v;
        };

        /// @brief count对象的大小取决于val的大小
        /// @param b 要比较的对象
        /// @return 小于b则为真，否则为假
        bool operator<(const CountItem b)
        {
            return val < b.val;
        };
    };

    /// @brief 从count_map中取出数据并按val值生成有序列表
    /// @return 一个列表指针
    std::vector<CountItem> *sortedCountList(void)
    {
        if (value_fd < 0)
        {
            return NULL;
        }
        auto keys = new psid[MAX_ENTRIES];
        auto vals = new char[MAX_ENTRIES * count_size];
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
            CountItem d(keys[i].pid, keys[i].ksid, keys[i].usid, data_value(vals + count_size * i));
            D->insert(std::lower_bound(D->begin(), D->end(), d), d);
        }
        delete[] keys;
        delete[] vals;
        return D;
    };

protected:
    int value_fd = -1; // 栈计数表的文件描述符
    int tgid_fd = -1;  // pid-tgid表的文件描述符
    int comm_fd = -1;  // pid-进程名表的文件描述符
    int trace_fd = -1; // 栈id-栈轨迹表的文件描述符

    // 计数变量类型默认为u32
    size_t count_size = sizeof(uint32_t);

    // 默认显示计数的变化情况，即每次输出数据后清除计数
    bool showDelta = true;

    /// @brief 将缓冲区的数据解析为特定值，默认解析为u32
    /// @param  无
    /// @return 解析出的值
    virtual double data_value(void *data)
    {
        return *(uint32_t *)data;
    };

    // 声明
#define declareEBPF(eBPFName) struct eBPFName *skel = NULL;

public:
    Scale scale;

    int pid = -1; // 用于设置ebpf程序跟踪的pid
    int cpu = -1; // 用于设置ebpf程序跟踪的cpu
    int err = 0;  // 用于保存错误代码

    bool ustack = true; // 是否跟踪用户栈
    bool kstack = true; // 是否跟踪内核栈
    uint64_t min = 0;
    uint64_t max = __UINT64_MAX__; // 设置采集指标最大值，最小值

    bool clear = false; // 清除已输出的指标积累量
    int self_pid;

    StackCollector()
    {
        self_pid = getpid();
    };

    /// @brief 负责ebpf程序的加载、参数设置和打开操作
    /// @param  无
    /// @return 成功则返回0，否则返回负数
    virtual int load(void) = 0;
#define defaultLoad                               \
	int load(void) override                       \
	{                                             \
		StackProgLoadOpen(skel->bss->apid = pid); \
		return 0;                                 \
	};

    /// @brief 将ebpf程序挂载到跟踪点上
    /// @param  无
    /// @return 成功则返回0，否则返回负数
    virtual int attach(void) = 0;
#define defaultAttach                                    \
	int attach(void) override                            \
	{                                                    \
		err = skel->attach(skel);                        \
		CHECK_ERR(err, "Failed to attach BPF skeleton"); \
		return 0;                                        \
	};

    /// @brief 断开ebpf的跟踪点和处理函数间的连接
    /// @param  无
    virtual void detach(void) = 0;
#define defaultDetach           \
	void detach(void) override  \
	{                           \
		if (skel)               \
		{                       \
			skel->detach(skel); \
		}                       \
	};

    /// @brief 卸载ebpf程序
    /// @param  无
    virtual void unload(void) = 0;
#define defaultUnload            \
	void unload(void) override   \
	{                            \
		if (skel)                \
		{                        \
			skel->destroy(skel); \
		}                        \
		skel = NULL;             \
	};

    operator std::string()
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
            for (auto id : *D)
            {
                oss << id.pid << '\t' << id.usid << '\t' << id.ksid << '\t' << id.val
                    << '\n';
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
};

class OnCPUStackCollector : public StackCollector
{
private:
    declareEBPF(on_cpu_count_bpf);
    const char *online_cpus_file = "/sys/devices/system/cpu/online";
    bool *online_mask = NULL;
    int *pefds = NULL, num_cpus = 0, num_online_cpus = 0;
    struct perf_event_attr attr = {0};
    struct bpf_link **links = NULL;
    unsigned long long freq = 49;

public:
    OnCPUStackCollector()
    {
        setScale(freq);
        err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
        CHECK_ERR_EXIT(err, "Fail to get online CPU numbers");
        num_cpus = libbpf_num_possible_cpus();
        CHECK_ERR_EXIT(num_cpus <= 0, "Fail to get the number of processors");
    };

    void setScale(uint64_t freq)
    {
        this->freq = freq;
        scale.Period = 1e9 / freq;
        scale.Type = "OnCPUTime";
        scale.Unit = "nanoseconds";
    }

    int load(void) override
    {
        FILE *fp = popen("cat /proc/kallsyms | grep \" avenrun\"", "r");
        CHECK_ERR(!fp, "Failed to draw flame graph");
        unsigned long *load_a;
        fscanf(fp, "%p", &load_a);
        pclose(fp);
        StackProgLoadOpen(skel->bss->load_a = load_a) return 0;
    };

    int attach(void) override
    {
        attr = {
                .type = PERF_TYPE_SOFTWARE, // hardware event can't be used
                .size = sizeof(attr),
                .config = PERF_COUNT_SW_CPU_CLOCK,
                .sample_freq = freq,
                .inherit = 1,
                .freq = 1, // use freq instead of period
        };
        pefds = (int *)malloc(num_cpus * sizeof(int));
        for (int i = 0; i < num_cpus; i++)
        {
            pefds[i] = -1;
        }
        links = (struct bpf_link **)calloc(num_cpus, sizeof(struct bpf_link *));
        for (int cpu = 0; cpu < num_cpus; cpu++)
        {
            /* skip offline/not present CPUs */
            if (cpu >= num_online_cpus || !online_mask[cpu])
            {
                continue;
            }
            /* Set up performance monitoring on a CPU/Core */
            int pefd = perf_event_open(&attr, pid, cpu, -1, 0);
            CHECK_ERR(pefd < 0, "Fail to set up performance monitor on a CPU/Core");
            pefds[cpu] = pefd;
            /* Attach a BPF program on a CPU */
            links[cpu] = bpf_program__attach_perf_event(skel->progs.do_stack, pefd); // 与内核bpf程序联系
            CHECK_ERR(!links[cpu], "Fail to attach bpf program");
        }
        return 0;
    }

    void detach(void) override
    {
        if (links)
        {
            for (int cpu = 0; cpu < num_cpus; cpu++)
            {

                bpf_link__destroy(links[cpu]);
            }
            free(links);
            links = NULL;
        }
        if (pefds)
        {
            for (int i = 0; i < num_cpus; i++)
            {
                if (pefds[i] >= 0)
                {
                    close(pefds[i]);
                }
            }
            free(pefds);
            pefds = NULL;
        }
    }

    defaultUnload;
};

class OffCPUStackCollector : public StackCollector
{
private:
    declareEBPF(off_cpu_count_bpf);

protected:
    defaultLoad;
    defaultAttach;
    defaultDetach;
    defaultUnload;

public:
    OffCPUStackCollector()
    {
        scale.Period = 1 << 20;
        scale.Type = "OffCPUTime";
        scale.Unit = "milliseconds";
    };
};

class MemoryStackCollector : public StackCollector
{
private:
    declareEBPF(mem_count_bpf);

protected:
    double data_value(void *d) override
    {
        return *(uint64_t *)d;
    }

public:
    char *object = (char *)"libc.so.6";

    MemoryStackCollector()
    {
        count_size = sizeof(uint64_t);
        kstack = false;
        showDelta = false;
        scale.Period = 1;
        scale.Type = "LeakedMomery";
        scale.Unit = "bytes";
    };

    int load(void) override
    {
        StackProgLoadOpen();
        return 0;
    };

    int attach(void) override
    {
        ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
        ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
        ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
        ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);
        ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
        ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);
        ATTACH_UPROBE_CHECKED(skel, free, free_enter);

        ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
        ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);
        ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

        err = skel->attach(skel);
        CHECK_ERR(err, "Failed to attach BPF skeleton");
        return 0;
    };

    void detach(void) override
    {
        skel->detach(skel);
#define destoryBPFLinkIfExist(name)          \
	if (skel->links.name)                    \
	{                                        \
		bpf_link__destroy(skel->links.name); \
	}
        destoryBPFLinkIfExist(malloc_enter);
        destoryBPFLinkIfExist(malloc_exit);
        destoryBPFLinkIfExist(calloc_enter);
        destoryBPFLinkIfExist(calloc_exit);
        destoryBPFLinkIfExist(realloc_enter);
        destoryBPFLinkIfExist(realloc_exit);
        destoryBPFLinkIfExist(free_enter);
        destoryBPFLinkIfExist(mmap_enter);
        destoryBPFLinkIfExist(mmap_exit);
        destoryBPFLinkIfExist(munmap_enter);
    };

    defaultUnload;
};

class IOStackCollector : public StackCollector
{
private:
    declareEBPF(io_count_bpf);

protected:
    double data_value(void *data) override
    {
        io_tuple *p = (io_tuple *)data;
        switch (DataType)
        {
            case AVE:
                return 1. * p->size / p->count;
            case SIZE:
                return p->size;
            case COUNT:
                return p->count;
            default:
                return 0;
        }
    };

public:
    typedef enum
    {
        COUNT,
        SIZE,
        AVE
    } io_mod;

    io_mod DataType = io_mod::COUNT;

    void setScale(io_mod mod)
    {
        DataType = mod;
        static const char *Types[] = {"IOCount", "IOSize", "AverageIOSize"};
        static const char *Units[] = {"counts", "bytes", "bytes"};
        scale.Type = Types[mod];
        scale.Unit = Units[mod];
        scale.Period = 1;
    };

    IOStackCollector()
    {
        count_size = sizeof(io_tuple);
        setScale(DataType);
    };

    defaultLoad;
    defaultAttach;
    defaultDetach;
    defaultUnload;
};

class ReadaheadStackCollector : public StackCollector
{
private:
    declareEBPF(pre_count_bpf);

protected:
    double data_value(void *data) override
    {
        ra_tuple *p = (ra_tuple *)data;
        return p->expect - p->truth;
    };

public:
    defaultLoad;
    defaultAttach;
    defaultDetach;
    defaultUnload;

    ReadaheadStackCollector()
    {
        count_size = sizeof(ra_tuple);
        showDelta = false;
        scale = {
                .Type = "UnusedReadaheadPages",
                .Unit = "pages",
                .Period = 1,
        };
    };
};

class StackCountStackCollector : public StackCollector
{
private:
    declareEBPF(stack_count_bpf);

public:
    std::string probe = ""; // 保存命令行的输入
    std::string tp_class = "";
    std::vector<std::string> strList;
    typedef enum
    {
        KPROBE,
        TRACEPOINT,
        USTD_TP,
        UPROBE
    } stack_mod;

    stack_mod ProbeType = stack_mod::KPROBE;

    StackCountStackCollector()
    {
        scale = {
                .Type = "StackCounts",
                .Unit = "Counts",
                .Period = 1,
        };
    };

    void setProbe(std::string probe)
    {
        splitString(probe, ':', strList);
        if (strList.size() == 1)
        {
            // probe a kernel function
            this->probe = probe;
        }
        else if (strList.size() == 3)
        {
            if (strList[0] == "p" && strList[1] == "")
            {
                // probe a kernel function
                this->probe = strList[2];
            }
            else if (strList[0] == "t")
            {
                // probe a kernel tracepoint
                this->tp_class = strList[1];
                this->probe = strList[2];
                ProbeType = stack_mod::TRACEPOINT;
            }
            else if (strList[0] == "p" && strList[1] != "")
            {
                // probe a user-space function in the library 'lib'
                ProbeType = stack_mod::UPROBE;
            }
            else if (strList[0] == "u")
            {
                // probe a USDT tracepoint
                ProbeType = stack_mod::USTD_TP;
            }
            else
            {
                printf("Type must be 'p', 't', or 'u'");
            }
        }
        else if (strList.size() == 2)
        {
            // probe a user-space function in the library 'lib'
            ProbeType = stack_mod::UPROBE;
        }
        else
        {
            printf("Too many args");
        }
        scale.Type = (probe + scale.Type).c_str();
    }

    defaultLoad;
    int attach(void) override
    {
        if (ProbeType == KPROBE)
        {
            skel->links.handle =
                    bpf_program__attach_kprobe(skel->progs.handle, false,
                                               probe.c_str());
            CHECK_ERR(!skel->links.handle, "Fail to attach kprobe");
        }
        else if (ProbeType == TRACEPOINT)
        {
            skel->links.handle_tp =
                    bpf_program__attach_tracepoint(skel->progs.handle_tp, tp_class.c_str(), probe.c_str());
            CHECK_ERR(!skel->links.handle_tp, "Fail to attach tracepoint");
        }
        return 0;
    };
    defaultDetach;
    defaultUnload;
};

namespace MainConfig
{
int run_time = __INT_MAX__; // 运行时间
unsigned delay = 5;			// 设置输出间隔
std::string command = "";
int32_t target_pid = -1;
}
std::vector<StackCollector *> StackCollectorList;
void endCollect(void)
{
    signal(SIGINT, SIG_IGN);
    for (auto Item : StackCollectorList)
    {
        if (MainConfig::run_time > 0)
        {
            std::cout << std::string(*Item) << std::endl;
        }
        Item->detach();
        Item->unload();
    }
    if (MainConfig::command.length())
    {
        kill(MainConfig::target_pid, SIGTERM);
    }
}

uint64_t IntTmp;
std::string StrTmp;
int main(int argc, char *argv[])
{
    auto MainOption = ((
            ((clipp::option("-p", "--pid") & clipp::value("pid of sampled process, default -1 for all", MainConfig::target_pid)) % "set pid of process to monitor") |
            ((clipp::option("-c", "--command") & clipp::value("to be sampled command to run, default none", MainConfig::command)) % "set command for monitoring the whole life")),
            (clipp::option("-d", "--delay") & clipp::value("delay time(seconds) to output, default 5", MainConfig::delay)) % "set the interval to output",
            (clipp::option("-t", "--timeout") & clipp::value("run time, default nearly infinite", MainConfig::run_time)) % "set the total simpling time");

    auto SubOption = (clipp::option("-U", "--user-stack-only").call([]
                                                                    { StackCollectorList.back()->kstack = false; }) %
                      "only sample user stacks",
            clipp::option("-K", "--kernel-stack-only").call([]
                                                            { StackCollectorList.back()->ustack = false; }) %
            "only sample kernel stacks",
            (clipp::option("-m", "--max-value") & clipp::value("max threshold of sampled value", IntTmp).call([]
                                                                                                              { StackCollectorList.back()->max = IntTmp; })) %
            "set the max threshold of sampled value",
            (clipp::option("-n", "--min-value") & clipp::value("min threshold of sampled value", IntTmp).call([]
                                                                                                              { StackCollectorList.back()->min = IntTmp; })) %
            "set the min threshold of sampled value");

    auto OnCpuOption = (clipp::option("on-cpu").call([]
                                                     { StackCollectorList.push_back(new OnCPUStackCollector()); }) %
                        "sample the call stacks of on-cpu processes") &
                       (clipp::option("-F", "--frequency") & clipp::value("sampling frequency", IntTmp).call([]
                                                                                                             { static_cast<OnCPUStackCollector *>(StackCollectorList.back())->setScale(IntTmp); }) %
                                                             "sampling at a set frequency",
                               SubOption);

    auto OffCpuOption = clipp::option("off-cpu").call([]
                                                      { StackCollectorList.push_back(new OffCPUStackCollector()); }) %
                        "sample the call stacks of off-cpu processes" &
                        SubOption;

    auto MemoryOption = clipp::option("mem").call([]
                                                  { StackCollectorList.push_back(new MemoryStackCollector()); }) %
                        "sample the memory usage of call stacks" &
                        SubOption;

    auto IOOption = clipp::option("io").call([]
                                             { StackCollectorList.push_back(new IOStackCollector()); }) %
                    "sample the IO data volume of call stacks" &
                    ((clipp::option("--mod") & (clipp::option("count").call([]
                                                                            { static_cast<IOStackCollector *>(StackCollectorList.back())->setScale(IOStackCollector::io_mod::COUNT); }) %
                                                "Counting the number of I/O operations" |
                                                clipp::option("ave").call([]
                                                                          { static_cast<IOStackCollector *>(StackCollectorList.back())->setScale(IOStackCollector::io_mod::AVE); }) %
                                                "Counting the ave of I/O operations" |
                                                clipp::option("size").call([]
                                                                           { static_cast<IOStackCollector *>(StackCollectorList.back())->setScale(IOStackCollector::io_mod::SIZE); }) %
                                                "Counting the size of I/O operations")) %
                     "set the statistic mod",
                            SubOption);

    auto ReadaheadOption = clipp::option("ra").call([]
                                                    { StackCollectorList.push_back(new ReadaheadStackCollector()); }) %
                           "sample the readahead hit rate of call stacks" &
                           SubOption;

    auto StackCountOption = clipp::option("stackcount").call([]
                                                             { StackCollectorList.push_back(new StackCountStackCollector()); }) %
                            "sample the counts of calling stacks" &
                            (clipp::option("-S", "--String") & clipp::value("probe String", StrTmp).call([]
                                                                                                         { static_cast<StackCountStackCollector *>(StackCollectorList.back())->setProbe(StrTmp); }) %
                                                               "sampling at a set probe string",
                                    SubOption);

    auto cli = (MainOption,
            clipp::option("-v", "--version").call([]
                                                  { std::cout << "verion 2.0\n\n"; }) %
            "show version",
            OnCpuOption,
            OffCpuOption,
            MemoryOption,
            IOOption,
            ReadaheadOption,
            StackCountOption) %
               "statistic call trace relate with some metrics";

    if (!clipp::parse(argc, argv, cli))
    {
        std::cout << clipp::make_man_page(cli, argv[0]) << '\n';
        return 0;
    }

    uint64_t eventbuff = 1;
    int child_exec_event_fd = eventfd(0, EFD_CLOEXEC);
    CHECK_ERR(child_exec_event_fd < 0, "failed to create event fd");
    if (MainConfig::command.length())
    {
        MainConfig::target_pid = fork();
        switch (MainConfig::target_pid)
        {
            case -1:
            {
                std::cout << "command create failed." << std::endl;
                return -1;
            }
            case 0:
            {
                const auto bytes = read(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
                CHECK_ERR(bytes < 0, "failed to read from fd %ld", bytes)
                else CHECK_ERR(bytes != sizeof(eventbuff), "read unexpected size %ld", bytes);
                printf("child exec %s\n", MainConfig::command.c_str());
                CHECK_ERR_EXIT(execl("/bin/bash", "bash", "-c", MainConfig::command.c_str(), NULL), "failed to execute child command");
                break;
            }
            default:
            {
                printf("create child %d\n", MainConfig::target_pid);
                break;
            }
        }
    }

    for (auto Item = StackCollectorList.begin(); Item != StackCollectorList.end();)
    {
        (*Item)->pid = MainConfig::target_pid;
        if ((*Item)->load())
        {
            goto err;
        }
        if ((*Item)->attach())
        {
            goto err;
        }
        Item++;
        continue;
        err:
        fprintf(stderr, "%s eBPF prog err\n", (*Item)->scale.Type);
        (*Item)->detach();
        (*Item)->unload();
        Item = StackCollectorList.erase(Item);
    }

    if (MainConfig::command.length())
    {
        printf("wake up child\n");
        write(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
    }

    // printf("display mode: %d\n", MainConfig::d_mode);

    for (; MainConfig::run_time > 0 && (MainConfig::target_pid < 0 || !kill(MainConfig::target_pid, 0)); MainConfig::run_time -= MainConfig::delay)
    {
        sleep(MainConfig::delay);
        for (auto Item : StackCollectorList)
        {
            Item->detach();
            std::cout << std::string(*Item);
            Item->attach();
        }
    }

    atexit(endCollect);
}