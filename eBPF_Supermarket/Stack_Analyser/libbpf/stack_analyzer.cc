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

#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <map>

#include "stack_analyzer.h"

#include "bpf/on_cpu_count.skel.h"
#include "bpf/off_cpu_count.skel.h"
#include "bpf/mem_count.skel.h"
#include "rapidjson/document.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/writer.h"
#include "symbol.h" /*符号解析库头文件*/

/// @brief  printing help information
/// @param progname progname printed in the help info
static void show_help(const char *progname)
{
	printf("Usage: %s [-f <frequency>] [-p <pid>] [-T <time>] [-m <0 on cpu|1 off cpu|2 mem>] "
		   "[-U user stack only] [-K kernel stack only] [-h help]\n",
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
	int run_time = 1;											  /*run time*/
	int freq = 1;												  /*simple frequency*/
	MOD mod = MOD_ON_CPU;										  /*mod setting*/
	bool u = true;												  /*user stack setting*/
	bool k = true;												  /*kernel stack setting*/
	char *object = (char *)"/usr/lib/x86_64-linux-gnu/libc.so.6"; /*executable binary file for uprobe*/
}

class bpf_loader
{
protected:
	int pid, cpu, err;
	bool ustack, kstack;
	virtual int psid_count(void) = 0, pid_tgid(void) = 0, pid_comm(void) = 0, stack_trace(void) = 0;
#define open_map(name) bpf_map__fd(skel->maps.name)
#define decl_open(name) \
	int name(void) { return open_map(name); }
#define DECL_ALL_OPEN      \
	decl_open(psid_count); \
	decl_open(pid_tgid);   \
	decl_open(pid_comm);   \
	decl_open(stack_trace);
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
	bpf_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : pid(p), cpu(c), ustack(u), kstack(k){};
	virtual int load(void) = 0, attach(void) = 0;
	virtual void detach(void) = 0, unload(void) = 0;
	int data_save(void)
	{
		rapidjson::Document ajson;
		rapidjson::Document::AllocatorType &alc = ajson.GetAllocator();
		ajson.SetObject();

		int tgid_fd = pid_tgid();
		std::map<int, int> pidtgid_map;
		CHECK_ERR(tgid_fd < 0, "tgid map open failure");
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
		close(tgid_fd);

		int comm_fd = pid_comm();
		CHECK_ERR(comm_fd < 0, "comm map open failure");
		comm cmd;
		for (int prev = 0, pid; !bpf_map_get_next_key(comm_fd, &prev, &pid); prev = pid)
		{
			bpf_map_lookup_elem(comm_fd, &pid, &cmd);
			std::string tgid_s = std::to_string(pidtgid_map[pid]);
			std::string pid_s = std::to_string(pid);
			ajson[tgid_s.c_str()][pid_s.c_str()].CKV("name", cmd.str, alc);
		}
		close(comm_fd);

		int count_fd = psid_count();
		CHECK_ERR(count_fd < 0, "count map open failure");
		int trace_fd = stack_trace();
		CHECK_ERR(trace_fd < 0, "trace map open failure");
		int count;
		symbol sym;
		__u64 ip[MAX_STACKS];
		std::string symbol;
		elf_file file;
		std::string unsymbol("UNKNOWN");
		for (psid prev = {0}, id; !bpf_map_get_next_key(count_fd, &prev, &id); prev = id)
		{
			bpf_map_lookup_elem(count_fd, &id, &count);
			std::string tgid_s = std::to_string(pidtgid_map[id.pid]);
			std::string pid_s = std::to_string(id.pid);
			auto stacks = ajson[tgid_s.c_str()][pid_s.c_str()]["stacks"].GetObject();
			auto sid_s = std::to_string(id.usid) + "," + std::to_string(id.ksid);
			auto sid_c = sid_s.c_str();
			stacks.KV(sid_c, rapidjson::kObjectType);
			stacks[sid_c].CKV("count", count);
			stacks[sid_c].CKV("trace", rapidjson::kArrayType);
			auto trace = stacks[sid_c]["trace"].GetArray();
			// symbolize
			if (id.ksid>=0){
				bpf_map_lookup_elem(trace_fd, &id.ksid, ip);
				for (auto p : ip)
				{
					sym.reset(p);
					if (g_symbol_parser.find_kernel_symbol(sym))
						trace.PV(sym.name.c_str());
					else
						trace.PV(unsymbol.c_str());
				}
			}
			else
				trace.PV("MISSING KERNEL STACK");
			if (id.usid>=0) {
				bpf_map_lookup_elem(trace_fd, &id.usid, ip);
				for (auto p : ip)
				{
					sym.reset(p);
					if (g_symbol_parser.find_symbol_in_cache(id.pid, p, symbol))
						trace.PV(symbol.c_str());
					else if (g_symbol_parser.get_symbol_info(id.pid, sym, file) &&
							 g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid))
					{
						trace.PV(sym.name.c_str());
						g_symbol_parser.putin_symbol_cache(id.pid, p, sym.name);
					} else {
						trace.PV(unsymbol.c_str());
						g_symbol_parser.putin_symbol_cache(pid, p, unsymbol);
					}
				}
			}
			else
				trace.PV("MISSING USER STACK");
		}
		close(trace_fd);
		close(count_fd);

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
		int count_fd = psid_count(), val;
		CHECK_ERR(count_fd < 0, "count map open failure");
		psid prev = {}, key; /*for traverse map*/
		do
		{
			printf("---------%d---------\n", count_fd);
			sleep(5);
			while (!bpf_map_get_next_key(count_fd, &prev, &key))
			{
				bpf_map_lookup_elem(count_fd, &key, &val);
				printf("%6d\t(%6d,%6d)\t%-6d\n", key.pid, key.ksid, key.usid, val);
				prev = key;
			}
			time -= 5;
		} while (time > 0);
		// close(count_fd);
		return time;
	};
	int test(void)
	{
		load();
		if (err)
			return -1;
		attach();
		if (err)
			return -1;
		count_log(env::run_time);
		detach();
		data_save();
		// unload();
		return 0;
	};
};

class on_cpu_loader : public bpf_loader
{
protected:
	int pefd;
	unsigned long long freq;
	struct perf_event_attr attr;
	struct on_cpu_count_bpf *skel;
	DECL_ALL_OPEN;

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
	int load(void)
	{
		skel = on_cpu_count_bpf__open_and_load();
		CHECK_ERR(!skel, "Fail to open and load BPF skeleton");
		skel->bss->u = ustack;
		skel->bss->k = kstack;
		return 0;
	};
	int attach(void)
	{
		pefd = perf_event_open(&attr, pid, -1, -1, PERF_FLAG_FD_CLOEXEC); // don't track child process
		CHECK_ERR(pefd < 0, "Fail to set up performance monitor on a CPU/Core");
		skel->links.do_stack = bpf_program__attach_perf_event(skel->progs.do_stack, pefd);
		CHECK_ERR(!(skel->links.do_stack), "Fail to attach bpf");
		return 0;
	}
	void detach(void)
	{
		if (skel->links.do_stack)
			bpf_link__destroy(skel->links.do_stack);
		if (pefd)
			close(pefd);
	}
	void unload(void)
	{
		if (skel)
			on_cpu_count_bpf__destroy(skel);
		skel = 0;
	}
};

class off_cpu_loader : public bpf_loader
{
protected:
	struct off_cpu_count_bpf *skel;
	DECL_ALL_OPEN;

public:
	off_cpu_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k)
	{
		skel = 0;
	};
	int load(void)
	{
		LOAD_CHECKED(off_cpu_count, skel);
		skel->bss->apid = pid;
		skel->bss->u = ustack;
		skel->bss->k = kstack;
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
			bpf_destroy(off_cpu_count, skel);
		skel = 0;
	};
};

class mem_loader : public bpf_loader
{
protected:
	struct mem_count_bpf *skel;
	char *object;
	DECL_ALL_OPEN;

public:
	mem_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k, char *e = env::object) : bpf_loader(p, c, u, k), object(e)
	{
		skel = 0;
	};
	int load(void)
	{
		skel = mem_count_bpf__open_and_load();
		CHECK_ERR(!skel, "Fail to open and load BPF skeleton");
		skel->bss->u = ustack;
		return 0;
	};
	int attach(void)
	{
		ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
		ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
		ATTACH_UPROBE_CHECKED(skel, free, free_enter);
		err = bpf_attach(mem_count, skel);
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
			bpf_destroy(mem_count, skel);
		skel = 0;
	};
};

int main(int argc, char *argv[])
{
	char argp;
	while ((argp = getopt(argc, argv, "hf:p:T:m:UK")) != -1) // parsing arguments
	{
		switch (argp)
		{
		case 'f':
			env::freq = atoi(optarg);
			if (env::freq < 1)
				env::freq = 1;
			break;
		case 'p':
			env::pid = atoi(optarg);
			if (env::pid < 1)
				env::pid = -1;
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
	bpf_loader *arr[3] = {
		new on_cpu_loader(),
		new off_cpu_loader(),
		new mem_loader(),
	};
	for (auto b : arr)
	{
		if (b->test())
			return -1;
	}
}