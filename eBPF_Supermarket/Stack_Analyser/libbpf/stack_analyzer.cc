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

#include "rapidjson/document.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/writer.h"
#include "symbol.h" /*符号解析库头文件*/

#ifdef __cplusplus
extern "C"
{
#endif

#include <paths.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <signal.h>

#include "stack_analyzer.h"
#include "bpf/on_cpu_count.skel.h"
#include "bpf/off_cpu_count.skel.h"
#include "bpf/mem_count.skel.h"
#include "bpf/io_count.skel.h"

#ifdef __cplusplus
}
#endif

/// @brief  printing help information
/// @param progname progname printed in the help info
static void show_help(const char *progname)
{
	printf("Usage: %s [-F <frequency>=49] [-p <pid>=-1] [-T <time>=INT_MAX] [-m <0 on cpu|1 off cpu|2 mem|3 io>=0] "
		   "[-U user stack only] [-K kernel stack only] [-f flame graph but not json] [-h help] \n",
		   progname);
}

/// @brief staring perf event
/// @param hw_event attribution of the perf event
/// @param pid the pid to track. 0 for the calling process. -1 for all processes.
/// @param cpu the cpu to track. -1 for all cpu
/// @param group_fd fd of event group leader
/// @param flags setting
/// @return fd of perf event
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
							unsigned long flags)
{
	return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

namespace env
{
	int pid = -1;												  /*pid filter*/
	int cpu = -1;												  /*cpu index*/
	unsigned run_time = __INT_MAX__;							  /*run time*/
	int freq = 49;												  /*simple frequency*/
	MOD mod = MOD_ON_CPU;										  /*mod setting*/
	bool u = true;												  /*user stack setting*/
	bool k = true;												  /*kernel stack setting*/
	bool fla = false;											  /*flame graph instead of json*/
	char *object = (char *)"/usr/lib/x86_64-linux-gnu/libc.so.6"; /*executable binary file for uprobe*/
	static volatile sig_atomic_t exiting;						  /*exiting flag*/
}

class bpf_loader
{
protected:
	int pid, cpu, err, count_fd, tgid_fd, comm_fd, trace_fd;
	bool ustack, kstack;
#define OPEN_MAP(name) bpf_map__fd(skel->maps.name)
#define OPEN_ALL_MAP                 \
	count_fd = OPEN_MAP(psid_count); \
	tgid_fd = OPEN_MAP(pid_tgid);    \
	comm_fd = OPEN_MAP(pid_comm);    \
	trace_fd = OPEN_MAP(stack_trace);
#define LO(name, ...)                              \
	skel = name##_bpf__open();                     \
	CHECK_ERR(!skel, "Fail to open BPF skeleton"); \
	__VA_ARGS__;                                   \
	err = name##_bpf__load(skel);                  \
	CHECK_ERR(err, "Fail to load BPF skeleton");   \
	OPEN_ALL_MAP
#define CKV(k, ...)                                 \
	AddMember(k,                                    \
			  rapidjson::Value(__VA_ARGS__).Move(), \
			  alc)
#define KV(k, ...)                                  \
	AddMember(rapidjson::Value(k, alc).Move(),      \
			  rapidjson::Value(__VA_ARGS__).Move(), \
			  alc)
#define PV(v) PushBack(rapidjson::Value(v, alc), alc)

public:
	bpf_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : pid(p), cpu(c), ustack(u), kstack(k)
	{
		count_fd = tgid_fd = comm_fd = trace_fd = -1;
		err = 0;
	};
	virtual int load(void) = 0, attach(void) = 0;
	virtual void detach(void) = 0, unload(void) = 0;
	int flame_save(void)
	{
		printf("saving flame...\n");
		CHECK_ERR(count_fd < 0, "count map open failure");
		CHECK_ERR(trace_fd < 0, "trace map open failure");
		CHECK_ERR(comm_fd < 0, "comm map open failure");
		int max_deep = 0;
		for (psid prev = {}, key; !bpf_map_get_next_key(count_fd, &prev, &key); prev = key)
		{
			__u64 ip[MAX_STACKS];
			bpf_map_lookup_elem(trace_fd, &key.usid, ip);
			int deep = 0;
			for (int i = 0; i < MAX_STACKS && ip[i]; i++)
				deep++;
			if (max_deep < deep)
				max_deep = deep;
		}
		std::ostringstream tex;
		for (psid prev = {}, id; !bpf_map_get_next_key(count_fd, &prev, &id); prev = id)
		{
			symbol sym;
			__u64 ip[MAX_STACKS];
			if (id.ksid >= 0)
			{
				bpf_map_lookup_elem(trace_fd, &id.ksid, ip);
				for (auto p : ip)
				{
					if (!p)
						break;
					sym.reset(p);
					if (g_symbol_parser.find_kernel_symbol(sym))
						tex << sym.name << '\n';
					else
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						tex << a << '\n';
						std::string s(a);
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
				}
			}
			else
				tex << "[MISSING KERNEL STACK]" << '\n';
			tex << "________________" << '\n';
			unsigned deep = 0;
			if (id.usid >= 0)
			{
				bpf_map_lookup_elem(trace_fd, &id.usid, ip);
				std::string *s = 0, symbol;
				elf_file file;
				for (auto p : ip)
				{
					if (!p)
						break;
					sym.reset(p);

					if (g_symbol_parser.find_symbol_in_cache(id.pid, p, symbol))
						s = &symbol;
					else if (g_symbol_parser.get_symbol_info(id.pid, sym, file) &&
							 g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid))
					{
						s = &sym.name;
						g_symbol_parser.putin_symbol_cache(id.pid, p, sym.name);
					}
					if (!s)
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						tex << a << '\n';
						std::string s(a);
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
					else
						tex << *s << '\n';
					deep++;
				}
			}
			else
			{
				tex << "[MISSING USER STACK]" << '\n';
				deep = 1;
			}
			deep = max_deep - deep;
			for (int i = 0; i < deep; i++)
			{
				tex << "_\n";
			}
			{
				char cmd[COMM_LEN];
				bpf_map_lookup_elem(comm_fd, &id.pid, cmd);
				tex << cmd << ' ' << id.pid << '\n';
			}
			int count;
			bpf_map_lookup_elem(count_fd, &id, &count);
			tex << count << "\n\n";
		}
		std::string tex_s = tex.str();
		FILE *fp = 0;
		// fp = fopen("flatex.log", "w");
		// CHECK_ERR(!fp, "Failed to save flame text");
		// fwrite(tex_s.c_str(), sizeof(char), tex_s.size(), fp);
		// fclose(fp);
		fp = popen("stackcollapse.pl | tee colps.log | flamegraph.pl > flame.svg", "w");
		CHECK_ERR(!fp, "Failed to draw flame graph");
		fwrite(tex_s.c_str(), sizeof(char), tex_s.size(), fp);

		pclose(fp);
		return 0;
	}
	int data_save(void)
	{
		printf("saving...\n");
		CHECK_ERR(comm_fd < 0, "comm map open failure");
		CHECK_ERR(tgid_fd < 0, "tgid map open failure");
		CHECK_ERR(count_fd < 0, "count map open failure");
		CHECK_ERR(trace_fd < 0, "trace map open failure");
		rapidjson::Document ajson;
		rapidjson::Document::AllocatorType &alc = ajson.GetAllocator();
		ajson.SetObject();

		std::map<int, int> pidtgid_map;
		for (int prev = 0, pid, tgid; !bpf_map_get_next_key(tgid_fd, &prev, &pid); prev = pid)
		{
			bpf_map_lookup_elem(tgid_fd, &pid, &tgid);

			std::string tgid_s = std::to_string(tgid);
			const char *tgid_c = tgid_s.c_str();
			ajson.KV(tgid_c, rapidjson::kObjectType);

			std::string pid_s = std::to_string(pid);
			const char *pid_c = pid_s.c_str();
			ajson[tgid_c].KV(pid_c, rapidjson::kObjectType);

			ajson[tgid_c][pid_c].CKV("stacks", rapidjson::kObjectType);
			pidtgid_map[pid] = tgid;
		}

		comm cmd;
		for (int prev = 0, pid; !bpf_map_get_next_key(comm_fd, &prev, &pid); prev = pid)
		{
			bpf_map_lookup_elem(comm_fd, &pid, &cmd);
			std::string tgid_s = std::to_string(pidtgid_map[pid]);
			std::string pid_s = std::to_string(pid);
			ajson[tgid_s.c_str()][pid_s.c_str()].CKV("name", cmd.str, alc);
		}

		std::string unsymbol("[UNKNOWN]");
		for (psid prev = {0}, id; !bpf_map_get_next_key(count_fd, &prev, &id); prev = id)
		{
			rapidjson::Value trace;
			{
				int count;
				bpf_map_lookup_elem(count_fd, &id, &count);
				rapidjson::Value stacks;
				{
					std::string tgid_s = std::to_string(pidtgid_map[id.pid]);
					std::string pid_s = std::to_string(id.pid);
					stacks = ajson[tgid_s.c_str()][pid_s.c_str()]["stacks"].GetObject();
				}
				auto sid_c = (std::to_string(id.usid) + "," + std::to_string(id.ksid)).c_str();
				// auto sid_c = sid_s.c_str();
				stacks.KV(sid_c, rapidjson::kObjectType);
				stacks[sid_c].CKV("count", count);
				stacks[sid_c].CKV("trace", rapidjson::kArrayType);
				trace = stacks[sid_c]["trace"].GetArray();
			}
			// symbolize
			symbol sym;
			__u64 ip[MAX_STACKS];
			if (id.ksid >= 0)
			{
				bpf_map_lookup_elem(trace_fd, &id.ksid, ip);
				for (auto p : ip)
				{
					if (!p)
						break;
					sym.reset(p);
					if (g_symbol_parser.find_kernel_symbol(sym))
					{
						unsigned offset = p - sym.start;
						char offs[20];
						sprintf(offs, "+0x%x", offset);
						std::string s = sym.name + std::string(offs);
						trace.PV(s.c_str());
					}
					else
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string s(a);
						trace.PV(a);
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
				}
			}
			else
				trace.PV("[MISSING KERNEL STACK]");
			trace.PV("----------------");
			if (id.usid >= 0)
			{
				std::string symbol;
				elf_file file;
				bpf_map_lookup_elem(trace_fd, &id.usid, ip);
				for (auto p : ip)
				{
					if (!p)
						break;
					sym.reset(p);
					std::string *s = 0;
					if (g_symbol_parser.find_symbol_in_cache(id.pid, p, symbol))
						s = &symbol;
					else if (g_symbol_parser.get_symbol_info(id.pid, sym, file) &&
							 g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid))
					{
						s = &sym.name;
						g_symbol_parser.putin_symbol_cache(id.pid, p, sym.name);
					}
					if (!s)
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string s(a);
						trace.PV(a);
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
					else
					{
						unsigned offset = p - sym.start;
						char offs[20];
						sprintf(offs, "+0x%x", offset);
						*s = *s + std::string(offs);
						trace.PV(s->c_str());
					}
				}
			}
			else
				trace.PV("[MISSING USER STACK]");
		}

		FILE *fp = fopen("stack_count.json", "w");
		char writeBuffer[65536];
		rapidjson::FileWriteStream os(fp, writeBuffer, sizeof(writeBuffer));
		rapidjson::Writer<rapidjson::FileWriteStream> writer(os);
		ajson.Accept(writer);
		fclose(fp);
		return 0;
	};
	int count_log(int time)
	{
		CHECK_ERR(count_fd < 0, "count map open failure");
		int val;
		/*for traverse map*/
		for (; !env::exiting && time > 0; time -= 5)
		{
			printf("---------%d---------\n", count_fd);
			sleep(5);
			for (psid prev = {}, key; !bpf_map_get_next_key(count_fd, &prev, &key); prev = key)
			{
				bpf_map_lookup_elem(count_fd, &key, &val);
				printf("%6d\t(%6d,%6d)\t%-6d\n", key.pid, key.ksid, key.usid, val);
			}
		};
		return time;
	};
	int test(void)
	{
		do
		{
			err = load();
			if (err)
				break;
			err = attach();
			if (err)
				break;
			count_log(env::run_time);
		} while (false);
		detach();
		if (env::fla)
			err = flame_save();
		else
			err = data_save();
		// unload();
		return err;
	};
};

class on_cpu_loader : public bpf_loader
{
protected:
	int pefd;
	unsigned long long freq;
	struct perf_event_attr attr;
	struct on_cpu_count_bpf *skel;

public:
	on_cpu_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k, unsigned long long f = env::freq) : bpf_loader(p, c, u, k), freq(f)
	{
		pefd = -1;
		attr = {
			.type = PERF_TYPE_SOFTWARE, // hardware event can't be used
			.size = sizeof(attr),
			.config = PERF_COUNT_SW_CPU_CLOCK,
			.sample_freq = freq,
			.freq = 1, // use freq instead of period
		};
		skel = 0;
	};
	int load(void) override
	{
		LO(on_cpu_count,
		   skel->bss->u = ustack,
		   skel->bss->k = kstack)
		return 0;
	};
	int attach(void) override
	{
		pefd = perf_event_open(&attr, pid, -1, -1, PERF_FLAG_FD_CLOEXEC); // don't track child process
		CHECK_ERR(pefd < 0, "Fail to set up performance monitor on a CPU/Core");
		skel->links.do_stack = bpf_program__attach_perf_event(skel->progs.do_stack, pefd);
		CHECK_ERR(!(skel->links.do_stack), "Fail to attach bpf");
		return 0;
	}
	void detach(void) override
	{
		if (skel->links.do_stack)
			bpf_link__destroy(skel->links.do_stack);
		if (pefd)
			close(pefd);
	}
	void unload(void) override
	{
		if (on_cpu_loader::skel)
			on_cpu_count_bpf__destroy(on_cpu_loader::skel);
		skel = 0;
	}
};

class off_cpu_loader : public bpf_loader
{
protected:
	struct off_cpu_count_bpf *skel;

public:
	off_cpu_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k)
	{
		skel = 0;
	};
	int load(void)
	{
		LO(off_cpu_count,
		   skel->bss->apid = pid,
		   skel->bss->u = ustack,
		   skel->bss->k = kstack)
		return 0;
	};
	int attach(void)
	{
		err = bpf_attach(off_cpu_count, skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void)
	{
		if (skel)
			off_cpu_count_bpf__detach(skel);
	};
	void unload(void)
	{
		if (skel)
			off_cpu_count_bpf__destroy(skel);
		skel = 0;
	};
};

class mem_loader : public bpf_loader
{
protected:
	struct mem_count_bpf *skel;
	char *object;

public:
	mem_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k, char *e = env::object) : bpf_loader(p, c, u, k), object(e)
	{
		skel = 0;
	};
	int load(void)
	{
		LO(mem_count,
		   skel->bss->u = ustack,
		   skel->bss->apid = pid)
		return 0;
	};
	int attach(void)
	{
		ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
		ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
		ATTACH_UPROBE_CHECKED(skel, free, free_enter);
		err = mem_count_bpf__attach(skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void)
	{
		if (skel->links.free_enter)
			bpf_link__destroy(skel->links.free_enter);
		if (skel->links.malloc_exit)
			bpf_link__destroy(skel->links.malloc_exit);
		if (skel->links.malloc_enter)
			bpf_link__destroy(skel->links.malloc_enter);
	};
	void unload(void)
	{
		if (skel)
			mem_count_bpf__destroy(skel);
		skel = 0;
	};
};

class io_loader : public bpf_loader
{
protected:
	struct io_count_bpf *skel;

public:
	io_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k)
	{
		skel = 0;
	};
	int load(void)
	{
		LO(io_count,
		   skel->bss->apid = pid,
		   skel->bss->u = ustack,
		   skel->bss->k = kstack)
		return 0;
	};
	int attach(void)
	{
		err = bpf_attach(io_count, skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void)
	{
		if (skel)
			io_count_bpf__detach(skel);
	};
	void unload(void)
	{
		if (skel)
			io_count_bpf__destroy(skel);
		skel = 0;
	};
};

typedef bpf_loader *(*bpf_load)();

void __handler(int)
{
	env::exiting = 1;
}

int main(int argc, char *argv[])
{
	char argp;
	while ((argp = getopt(argc, argv, "hF:p:T:m:UKf")) != -1) // parsing arguments
	{
		switch (argp)
		{
		case 'F':
			env::freq = atoi(optarg);
			if (env::freq < 1)
				env::freq = 1;
			break;
		case 'p':
			env::pid = atoi(optarg);
			if (env::pid < 1)
				env::pid = -1;
			break;
		case 'f':
			env::fla = true;
			break;
		case 'T':
			env::run_time = atoi(optarg);
			break;
		case 'm':
			env::mod = (MOD)atoi(optarg);
			break;
		case 'U':
			env::k = 0; // do not track kernel stack
			break;
		case 'K':
			env::u = 0; // do not track user stack
			break;
		case 'h':
		default:
			show_help(argv[0]);
			return 0;
		}
	}
	bpf_load arr[] = {
		[]() -> bpf_loader *
		{ return new on_cpu_loader(); },
		[]() -> bpf_loader *
		{ return new off_cpu_loader(); },
		[]() -> bpf_loader *
		{ return new mem_loader(); },
		[]() -> bpf_loader *
		{ return new io_loader(); },
	};
	CHECK_ERR(signal(SIGINT, __handler) == SIG_ERR, "can't set signal handler");
	return arr[env::mod]()->test();
}