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
#include <iomanip>
#include <fstream>
#include <cxxabi.h>
#include <string.h>
#include <typeinfo>

#include "rapidjson/document.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/writer.h"
#include "symbol.h"
#include "clipp.h"


extern "C"
{
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "sa_user.h"
#include "bpf/on_cpu_count.skel.h"
#include "bpf/off_cpu_count.skel.h"
#include "bpf/mem_count.skel.h"
#include "bpf/io_count.skel.h"
#include "bpf/pre_count.skel.h"
}

// 模板用来统一调用多个类有同样但未被抽象的接口
// 虚函数用来规范接口来被统一调用



std::string demangle(const char *symbol) {
    size_t size = 0;
    int status = 0;
    char *demangled = abi::__cxa_demangle(symbol, NULL, &size, &status);

    if (status == 0 && demangled != NULL) {
        std::string result;
		for(size_t i=0;i<size;++i){
			if(demangled[i]=='(')
				break;

			result+=demangled[i];
		}
        free(demangled);
        return result;
    } else {
        // 解码失败，返回原始符号
        return symbol;
    }
}

class StackCollector
{
private:
	/// @brief count类，主要是为了重载比较运算，便于自动排序
	class CountItem
	{
	public:
		uint32_t pid;
		int32_t ksid, usid;
		uint64_t val;
		CountItem(int32_t p, int32_t k, int32_t u, uint64_t v)
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
		std::vector<CountItem> *D = new std::vector<CountItem>();
		for (psid prev = {0}, id; !bpf_map_get_next_key(value_fd, &prev, &id); prev = id)
		{
			bpf_map_lookup_elem(value_fd, &id, data_buf);
			CountItem d(id.pid, id.ksid, id.usid, data_value());
			D->insert(std::lower_bound(D->begin(), D->end(), d), d);
		}
		return D;
	};

protected:
	int value_fd = -1; // 栈计数表的文件描述符
	int tgid_fd = -1;  // pid-tgid表的文件描述符
	int comm_fd = -1;  // pid-进程名表的文件描述符
	int trace_fd = -1; // 栈id-栈轨迹表的文件描述符

	void *data_buf = NULL; // 用于存储单个指标值的缓冲区

	bool showDelta = true;

	/// @brief 将缓冲区的数据解析为特定值
	/// @param  无
	/// @return 解析出的值
	virtual uint64_t data_value(void) { return *(uint64_t *)data_buf; };

	/// @brief 为特定值添加注解
	/// @param f 特定值
	/// @return 字符串
	virtual std::string data_str(uint64_t f) { return "value:" + std::to_string(f); };

#define declareEBPF(eBPFName) \
	struct eBPFName *skel = NULL;

public:
	std::string name; // 标识类名

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
		data_buf = new uint64_t(0);
	};

	virtual ~StackCollector()
	{
		delete (uint64_t *)data_buf;
	};

	/// @brief 负责ebpf程序的加载、参数设置和打开操作
	/// @param  无
	/// @return 成功则返回0，否则返回负数
	virtual int load(void) = 0;
#define defaultLoad                 \
	int load(void) override         \
	{                               \
		StackProgLoadOpen(          \
			skel->bss->apid = pid); \
		return 0;                   \
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

	/// @brief 清除count map的数据
	/// @param  无
	void check_clear_count(void)
	{
		if (!showDelta)
			return;
		uint c = MAX_ENTRIES;
		for (psid prev = {0}, id; c && !bpf_map_get_next_key(value_fd, &prev, &id); c--, prev = id)
		{
			bpf_map_delete_elem(value_fd, &id);
		}
	}

	/// @brief 打印count列表
	/// @param  无
	void print_list(void)
	{
		auto D = sortedCountList();
		for (auto id : *D)
		{
			printf("pid:%-6d\tusid:%-6d\tksid:%-6d\t%s\n", id.pid, id.usid, id.ksid, data_str(id.val).c_str());
		}
		delete D;
	}

	/// @brief 将表中的栈数据保存为火焰图
	/// @param  无
	/// @return 表未成功打开则返回负数
	std::ostringstream *format(void)
	{
		CHECK_ERR_VALUE(value_fd < 0, nullptr, "count map open failure");
		CHECK_ERR_VALUE(trace_fd < 0, nullptr, "trace map open failure");
		CHECK_ERR_VALUE(comm_fd < 0, nullptr, "comm map open failure");
		// std::filebuf DataFileBuf;
		// const std::string DataFileName = name + "_stack_data.log";
		// CHECK_ERR(DataFileBuf.open(DataFileName, std::ios::app) == nullptr, "data file open failed");
		// std::ostream DataText(&DataFileBuf);
		auto DataTextP = new std::ostringstream();
		auto &DataText = *DataTextP;
		for (psid prev = {}, id; !bpf_map_get_next_key(value_fd, &prev, &id); prev = id)
		{
			{
				char cmd[COMM_LEN];
				bpf_map_lookup_elem(comm_fd, &id.pid, cmd);
				DataText << std::string(cmd) << ':' << std::to_string(id.pid) << ';';
			}
			symbol sym;
			uint64_t ip[MAX_STACKS];
			if (id.usid >= 0)
			{
				bpf_map_lookup_elem(trace_fd, &id.usid, ip);
				std::string *s = 0, symbol;
				elf_file file;
				uint64_t *p = ip + MAX_STACKS - 1;
				for (; !*p; p--)
					;
				for (; p >= ip; p--)
				{
					uint64_t &addr = *p;
					sym.reset(addr);
					if (g_symbol_parser.find_symbol_in_cache(id.pid, addr, symbol))
					{
						s = &symbol;
						if ((*s)[0] == '_' && (*s)[1] == 'Z')//代表是C++符号，则调用demangle解析
						{		
							*s = demangle(symbol.c_str());
						}
						DataText << *s << ';';
					}
					else if (g_symbol_parser.get_symbol_info(id.pid, sym, file) &&
							 g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid))
					{
						std::stringstream ss("");
						ss << "+0x" << std::hex << (addr - sym.ip);
						if (sym.name[0] == '_' && sym.name[1] == 'Z')//代表是C++符号，则调用demangle解析
						{	
							sym.name = demangle(sym.name.c_str());
						}
						// int sym_len = sym.name.length();
						// if (sym.name[sym_len-1] == ')' && sym.name[sym_len-2] == '(')//代表函数名加了括号
						// {	
						// 	DataText << "";
						// }else{
						// 	sym.name+="()";
						// }
						sym.name += ss.str();
						DataText << sym.name << ';';
						g_symbol_parser.putin_symbol_cache(id.pid, addr, sym.name);
					}
					else
					{
						std::stringstream ss("");
						ss << "0x" << std::hex << addr;
						auto addr_str = ss.str();
						DataText << addr_str << ';';
						g_symbol_parser.putin_symbol_cache(id.pid, addr, addr_str);
					}
				}
			}
			else
			{
				DataText << "[MISSING USER STACK];";
			}
			DataText << "---------;";
			if (id.ksid >= 0)
			{
				bpf_map_lookup_elem(trace_fd, &id.ksid, ip);
				uint64_t *p = ip + MAX_STACKS - 1;
				for (; !*p; p--)
					;
				for (; p >= ip; p--)
				{
					uint64_t &addr = *p;
					sym.reset(addr);
					if (g_symbol_parser.find_kernel_symbol(sym))		
					{
						if (sym.name[0] == '_' && sym.name[1] == 'Z')//代表是C++符号，则调用demangle解析
						{		
							sym.name = demangle(sym.name.c_str());
						}
						// int sym_len = sym.name.length();
						// if (sym.name[sym_len-1] == ')' && sym.name[sym_len-2] == '(')//代表函数名加了括号
						// {	
						// 	DataText << "";
						// }else{
						// 	sym.name+="()";
						// }
						DataText << sym.name << ';';
					}
					else
					{
						std::stringstream ss("");
						ss << "0x" << std::hex << addr;
						auto addr_str = ss.str();
						DataText << addr_str << ';';
						g_symbol_parser.putin_symbol_cache(pid, addr, addr_str);
					}
				}
			}
			else
			{
				DataText << "[MISSING KERNEL STACK];";
			}
			bpf_map_lookup_elem(value_fd, &id, data_buf);
			DataText << ' ' + std::to_string(data_value()) << '\n';
		}
		return DataTextP;
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

public:
	unsigned long long freq = 49;

	OnCPUStackCollector()
	{
		name = "on_cpu";
		err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
		CHECK_ERR_EXIT(err, "Fail to get online CPU numbers");
		num_cpus = libbpf_num_possible_cpus();
		CHECK_ERR_EXIT(num_cpus <= 0, "Fail to get the number of processors");
	};

	std::string data_str(uint64_t f) override { return "counts:" + std::to_string(f); };

	int load(void) override
	{
		FILE *fp = popen("cat /proc/kallsyms | grep \" avenrun\"", "r");
		CHECK_ERR(!fp, "Failed to draw flame graph");
		unsigned long *load_a;
		fscanf(fp, "%p", &load_a);
		pclose(fp);
		StackProgLoadOpen(
			skel->bss->load_a = load_a) return 0;
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
	std::string data_str(uint64_t f) override { return "time(ms):" + std::to_string(f); };
	defaultLoad;
	defaultAttach;
	defaultDetach;
	defaultUnload;

public:
	OffCPUStackCollector() { name = "off-cpu"; };
};

class MemoryStackCollector : public StackCollector
{
private:
	declareEBPF(mem_count_bpf);

protected:
	std::string data_str(uint64_t f) override { return "size(Byte):" + std::to_string(f); };

public:
	char *object = (char *)"libc.so.6";

	MemoryStackCollector()
	{
		kstack = false;
		name = "memory";
		showDelta = false;
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
	std::string data_str(uint64_t f) override
	{
		const std::string IOScale[] = {"counts", "size(B)", "aver(B/1)"};
		return IOScale[DataType] + ":" + std::to_string(f);
	};

	uint64_t data_value() override
	{
		io_tuple *p = (io_tuple *)data_buf;
		switch (DataType)
		{
		case AVE:
			return p->size / p->count;
		case SIZE:
			return p->size;
		case COUNT:
			return p->count;
		default:
			return 0;
		}
	};

public:
	io_mod DataType = io_mod::COUNT;

	IOStackCollector()
	{
		delete (uint64_t *)data_buf;
		data_buf = new io_tuple{0};
		name = "io";
	};

	~IOStackCollector() override
	{
		delete (io_tuple *)data_buf;
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
	std::string data_str(uint64_t f) override
	{
		return "rest_pages:" + std::to_string(f);
	};

	uint64_t data_value() override
	{
		ra_tuple *p = (ra_tuple *)data_buf;
		return p->expect - p->truth;
	};

public:
	defaultLoad;
	defaultAttach;
	defaultDetach;
	defaultUnload;

	ReadaheadStackCollector()
	{
		delete (uint64_t *)data_buf;
		data_buf = new ra_tuple{0};
		name = "readahead";
		showDelta = false;
	};

	~ReadaheadStackCollector() override
	{
		delete (ra_tuple *)data_buf;
	}
};

namespace MainConfig
{
	int run_time = __INT_MAX__;				 // 运行时间
	unsigned delay = 5;						 // 设置输出间隔
	display_t d_mode = display_t::NO_OUTPUT; // 设置显示模式
	std::string command = "";
	int32_t target_pid = -1;
	std::string server_address = "127.0.0.1:12345";
};

std::vector<StackCollector *> StackCollectorList;
void endCollect(void)
{
	signal(SIGINT, SIG_IGN);
	for (auto Item : StackCollectorList)
	{
		if (MainConfig::run_time > 0)
		{
			Item->format();
		}
		Item->detach();
		Item->unload();
	}
	if (MainConfig::command.length())
	{
		kill(MainConfig::target_pid, SIGTERM);
	}
}

uint64_t optbuff;
int main(int argc, char *argv[])
{
	auto MainOption = ((
						   ((clipp::option("-p", "--pid") & clipp::value("pid of sampled process, default -1 for all", MainConfig::target_pid)) % "set pid of process to monitor") |
						   ((clipp::option("-c", "--command") & clipp::value("to be sampled command to run, default none", MainConfig::command)) % "set command for monitoring the whole life")),
					   (clipp::option("-d", "--delay") & clipp::value("delay time(seconds) to output, default 5", MainConfig::delay)) % "set the interval to output",
					   clipp::option("-l", "--realtime-list").set(MainConfig::d_mode, LIST_OUTPUT) % "output in console, default false",
					   clipp::option("-t", "--timeout") & clipp::value("run time, default nearly infinite", MainConfig::run_time) % "set the total simpling time",
					   clipp::option("-s", "--server") & clipp::value("server address, default 127.0.0.1:12345", MainConfig::server_address) % "set the server address");

	auto SubOption = (clipp::option("-U", "--user-stack-only").call([]
																	{ StackCollectorList.back()->kstack = false; }) %
						  "only sample user stacks",
					  clipp::option("-K", "--kernel-stack-only").call([]
																	  { StackCollectorList.back()->ustack = false; }) %
						  "only sample kernel stacks",
					  (clipp::option("-m", "--max-value") & clipp::value("max threshold of sampled value", optbuff).call([]
																														 { StackCollectorList.back()->max = optbuff; })) %
						  "set the max threshold of sampled value",
					  (clipp::option("-n", "--min-value") & clipp::value("min threshold of sampled value", optbuff).call([]
																														 { StackCollectorList.back()->min = optbuff; })) %
						  "set the min threshold of sampled value");

	auto OnCpuOption = clipp::option("on-cpu").call([]
													{ StackCollectorList.push_back(new OnCPUStackCollector()); }) %
						   "sample the call stacks of on-cpu processes" &
					   (clipp::option("-F", "--frequency") & clipp::value("sampling frequency", optbuff).call([]
																											  { static_cast<OnCPUStackCollector *>(StackCollectorList.back())->freq = optbuff; }) %
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
																			{ static_cast<IOStackCollector *>(StackCollectorList.back())->DataType = COUNT; }) %
													"Counting the number of I/O operations" |
												clipp::option("ave").call([]
																		  { static_cast<IOStackCollector *>(StackCollectorList.back())->DataType = AVE; }) %
													"Counting the ave of I/O operations" |
												clipp::option("size").call([]
																		   { static_cast<IOStackCollector *>(StackCollectorList.back())->DataType = SIZE; }) %
													"Counting the size of I/O operations")) %
						 "set the statistic mod",
					 SubOption);

	auto ReadaheadOption = clipp::option("ra").call([]
													{ StackCollectorList.push_back(new ReadaheadStackCollector()); }) %
							   "sample the readahead hit rate of call stacks" &
						   SubOption;

	auto cli = (MainOption,
				clipp::option("-v", "--version").call([]
													  { std::cout << "verion 2.0\n\n"; }) %
					"show version",
				OnCpuOption,
				OffCpuOption,
				MemoryOption,
				IOOption,
				ReadaheadOption) %
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
		fprintf(stderr, "%s eBPF prog err\n", (*Item)->name.c_str());
		(*Item)->detach();
		(*Item)->unload(); // segment fault
		Item = StackCollectorList.erase(Item);
	}

	if (MainConfig::command.length())
	{
		printf("wake up child\n");
		write(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
	}

	printf("display mode: %d\n", MainConfig::d_mode);

	// 创建 socket
	bool ToRemote = true;
	int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == -1)
	{
		std::cerr << "Error creating socket" << std::endl;
		// return -1;
		ToRemote = false;
	}
	else
	{
		// 服务器地址信息
		sockaddr_in serverAddress;
		serverAddress.sin_family = AF_INET;
		auto ColonPos = MainConfig::server_address.find(':');
		if (ColonPos < 0)
		{
			std::cerr << "server address err" << std::endl;
			return 0;
		}
		auto IPAddr = MainConfig::server_address.substr(0, ColonPos);
		auto PortAddr = MainConfig::server_address.substr(ColonPos + 1);
		serverAddress.sin_port = htons(std::stoi(PortAddr));
		inet_pton(AF_INET, IPAddr.c_str(), &serverAddress.sin_addr);
		// 连接到服务器
		if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
		{
			std::cerr << "Error connecting to server" << std::endl;
			close(clientSocket);
			// return -1;
			ToRemote = false;
		}
	}

	for (; MainConfig::run_time > 0 && (MainConfig::target_pid < 0 || !kill(MainConfig::target_pid, 0)); MainConfig::run_time -= MainConfig::delay)
	{
		sleep(MainConfig::delay); // 模拟实时性
		time_t timep;
		::time(&timep);
		printf("%s", ctime(&timep));

		for (auto Item : StackCollectorList)
		{
			Item->detach();
			// if(MainConfig::d_mode == display_t::LIST_OUTPUT) {
			// 	Item->print_list();
			// }
			auto StreamData = Item->format();
			if (!StreamData)
			{
				continue;
			}
			auto dataToSend = StreamData->str();
			if (ToRemote)
			{
				// 发送数据到服务器
				struct diy_header AHeader = {
					.len = dataToSend.size()};
				strcpy(AHeader.name, Item->name.c_str());
				send(clientSocket, &AHeader, sizeof(AHeader), 0);
				send(clientSocket, dataToSend.c_str(), AHeader.len, 0);
			}
			else
			{
				Item->print_list();
				std::ofstream fout;
				fout.open(Item->name + "_stack_data.txt", std::ios::out | std::ios::app);
				fout << dataToSend;
			}
			delete StreamData;
			Item->check_clear_count();

			Item->attach();
		}
	}
	// 关闭连接
	close(clientSocket);
	atexit(endCollect);
}