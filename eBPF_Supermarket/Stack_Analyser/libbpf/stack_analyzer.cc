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
#include "clipp.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/wait.h>

#include "stack_analyzer.h"
#include "bpf/on_cpu_count.skel.h"
#include "bpf/off_cpu_count.skel.h"
#include "bpf/mem_count.skel.h"
#include "bpf/io_count.skel.h"
#include "bpf/pre_count.skel.h"

#ifdef __cplusplus
}
#endif

namespace env {
	int pid = -1;												  /*pid filter*/
	int cpu = -1;												  /*cpu index*/
	int run_time = __INT_MAX__;									  /*run time*/
	int freq = 49;												  /*simple frequency*/
	MOD mod = MOD_ON_CPU;										  /*mod setting*/
	bool u = true;												  /*user stack setting*/
	bool k = true;												  /*kernel stack setting*/
	bool fla = false;											  /*flame graph instead of json*/
	char *object = (char *)"libc.so.6"; /*executable binary file for uprobe*/
	static volatile sig_atomic_t exiting, child_exited;			  /*exiting flag*/
	static int child_exec_event_fd = -1;
	std::string command = "";
	bool count = true; /*for io counts*/
	int max = __INT_MAX__;
	int min = 0;
	unsigned delay = 5;
	display_t d_mode = NO_OUTPUT;
	bool clear = false; /*clear data after every show*/
	DATA data = COUNT;
}

void __handler(int signo) {
	// printf("sig %d %d\n", signo, kill(env::pid, 0));
	switch (signo) {
	case SIGCHLD:
		if (waitpid(env::pid, NULL, WNOHANG)) { // 子进程主动退出的情况 
			env::exiting = env::child_exited = 1;
		}
		break;
	case SIGINT:
		env::exiting = 1;
		break;
	default:
		break;
	}
}

class bpf_loader
{
protected:
	int pid;	  // 用于设置ebpf程序跟踪的pid
	int cpu;	  // 用于设置ebpf程序跟踪的cpu
	int err;	  // 用于保存错误代码
	int value_fd; // 栈计数表的文件描述符
	int tgid_fd;  // pid-tgid表的文件描述符
	int comm_fd;  // pid-进程名表的文件描述符
	int trace_fd; // 栈id-栈轨迹表的文件描述符
	bool ustack;  // 是否跟踪用户栈
	bool kstack;  // 是否跟踪内核栈
	uint64_t min, max;
	unsigned delay;
	display_t d_mode;
	void *data_buf;

	/// @brief 将缓冲区的数据解析为特定值
	/// @param  无
	/// @return 解析出的值
	virtual uint64_t data_value(void) {
		return *(uint64_t *)data_buf;
	};

	/// @brief 为特定值添加注解
	/// @param f 特定值
	/// @return 字符串
	virtual std::string data_str(uint64_t f) { 
		return "value:" + std::to_string(f); 
	};

	/// @brief count类，主要是为了重载比较运算，便于自动排序
	class pksid_val {
	public:
		uint32_t pid;
		int32_t ksid, usid;
		uint64_t val;
		pksid_val(int32_t p, int32_t k, int32_t u, uint64_t v) {
			pid = p;
			ksid = k;
			usid = u;
			val = v;
		};

		/// @brief count对象的大小取决于val的大小
		/// @param b 要比较的对象
		/// @return 小于b则为真，否则为假
		bool operator<(const pksid_val b) { 
			return val < b.val; 
		};
	};

	/// @brief 从count_map中取出数据并按val值生成有序列表
	/// @return 一个列表指针
	std::vector<pksid_val> *sortD() {
		if (value_fd < 0) {
			return NULL;
		}
		std::vector<pksid_val> *D = new std::vector<pksid_val>();
		for (psid prev = {0}, id; !bpf_map_get_next_key(value_fd, &prev, &id); prev = id) {
			bpf_map_lookup_elem(value_fd, &id, data_buf);
			pksid_val d(id.pid, id.ksid, id.usid, data_value());
			D->insert(std::lower_bound(D->begin(), D->end(), d), d);
		}
		return D;
	};

	/// @brief 缓存用户态程序符号
	/// @param pid 用户态进程号
	/// @param usid 用户态调用栈号
	void cache_user_syms(unsigned pid, int usid) {
		if (usid >= 0) {
			__u64 ip[MAX_STACKS];
			bpf_map_lookup_elem(trace_fd, &usid, ip);
			std::string symbol;
			struct symbol sym;
			elf_file file;
			for (auto p : ip) {
				if (!p) {
					break;
				}
				sym.reset(p);

				if (g_symbol_parser.find_symbol_in_cache(pid, p, symbol)) {
					continue;
				}
				if (g_symbol_parser.get_symbol_info(pid, sym, file) &&
					g_symbol_parser.find_elf_symbol(sym, file, pid, pid)) {
					g_symbol_parser.putin_symbol_cache(pid, p, sym.name);
				}
			}
		}
	}

	/// @brief 打印count列表
	/// @param  无
	void print_list(void)
	{
		auto D = sortD();
		for (auto id : *D) {
			cache_user_syms(id.pid, id.usid);
			printf("pid:%-6d\tusid:%-6d\tksid:%-6d\t%s\n", id.pid, id.usid, id.ksid, data_str(id.val).c_str());
		}
		delete D;
	}

	/// @brief 缓存 count_map中记录的所有进程的用户态程序的 函数符号
	/// @param  无
	void traverse_cache(void)
	{
		for (psid prev = {0}, id; !bpf_map_get_next_key(value_fd, &prev, &id); prev = id) {
			cache_user_syms(id.pid, id.usid);
		}
	}

	/// @brief 清除count map的数据
	/// @param  无
	void clear_count(void)
	{
		uint c = MAX_ENTRIES;
		for (psid prev = {0}, id; c && !bpf_map_get_next_key(value_fd, &prev, &id); c--, prev = id) {
			bpf_map_delete_elem(value_fd, &id);
		}
	}

	/// @brief 每隔5s输出计数表中的栈及数量
	/// @param time 输出的持续时间
	/// @return 返回被强制退出时的剩余时间，计数表未打开则返回-1
	int log(int time) {
		CHECK_ERR(value_fd < 0, "count map open failure");
		/*for traverse map*/
		time_t timep;
		for (; !env::exiting && time > 0 && (pid < 0 || !kill(pid, 0)); time -= delay) {
			// printf("exiting:%d, time:%d, pid:%d, existing:%d\n", env::exiting, time, pid, kill(pid, 0));
			sleep(delay);
			::time(&timep);
			printf("%s", ctime(&timep));
			switch (d_mode)
			{
			case FLAME_OUTPUT:
				flame_save();
				break;
			case LIST_OUTPUT:
				print_list();
				break;
			default:
				traverse_cache();
				break;
			}
		};
		if (env::clear && time > 0 && !env::exiting) {
			clear_count();
		}
		return time;
	};

	/// @brief 创建子进程以执行特定命令
	/// @return 无
	int exec_command(void) {
		// if specific userspace program was specified,
		// create the child process and use an eventfd to synchronize the call to exec()
		CHECK_ERR(env::pid >= 0, "cannot specify both command and pid");
		CHECK_ERR(event_init(&env::child_exec_event_fd), "failed to init child event");
		env::pid = pid = fork_sync_exec(env::command.c_str(), env::child_exec_event_fd);
		CHECK_ERR(pid < 0, "failed to spawn child process");
		return 0;
	};

	/// @brief 唤醒子进程以开始执行特定的命令
	/// @return 无
	int activate_child(void) {
		int ret = event_notify(env::child_exec_event_fd, 1);
		CHECK_ERR(ret, "failed to notify child to perform exec");
		return 0;
	};

	/// @brief 清除创建的用于执行监测命令的子进程
	/// @return 无
	int clear_child(void) {
		if (!env::child_exited) { // 子进程未主动退出的情况
			CHECK_ERR(kill(env::pid, SIGTERM), "failed to signal child process");
			printf("signaled child process\n");
			CHECK_ERR(waitpid(env::pid, NULL, 0) < 0, "failed to reap child process");
			printf("reaped child process\n");
		}
		return 0;
	};

public:
	bpf_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k,
				unsigned d = env::delay, display_t disp = env::d_mode, uint64_t n = env::min,
				uint64_t m = env::max
			) : pid(p), cpu(c), ustack(u), kstack(k), min(n), max(m), delay(d), d_mode(disp) {
		value_fd = tgid_fd = comm_fd = trace_fd = -1;
		err = 0;
		data_buf = new uint64_t(0);
	};

	virtual ~bpf_loader() {
		delete (uint64_t *)data_buf;
	};

	/// @brief 负责ebpf程序的加载、参数设置和打开操作
	/// @param  无
	/// @return 成功则返回0，否则返回负数
	virtual int load(void) = 0;

	/// @brief 将ebpf程序挂载到跟踪点上
	/// @param  无
	/// @return 成功则返回0，否则返回负数
	virtual int attach(void) = 0;

	/// @brief 断开ebpf的跟踪点和处理函数间的连接
	/// @param  无
	virtual void detach(void) = 0;

	/// @brief 卸载ebpf程序
	/// @param  无
	virtual void unload(void) = 0;

	/// @brief 将表中的栈数据保存为火焰图
	/// @param  无
	/// @return 表未成功打开则返回负数
	int flame_save(void)
	{
		printf("saving flame...\n");
		CHECK_ERR(value_fd < 0, "count map open failure");
		CHECK_ERR(trace_fd < 0, "trace map open failure");
		CHECK_ERR(comm_fd < 0, "comm map open failure");
		std::ostringstream tex("");
		for (psid prev = {}, id; !bpf_map_get_next_key(value_fd, &prev, &id); prev = id) {
			std::string line("");
			symbol sym;
			__u64 ip[MAX_STACKS];
			if (id.ksid >= 0) {
				bpf_map_lookup_elem(trace_fd, &id.ksid, ip);
				for (auto p : ip) {
					if (!p) {
						break;
					}
					sym.reset(p);
					if (g_symbol_parser.find_kernel_symbol(sym)) {
						line = sym.name + ';' + line;
					} else {
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string s(a);
						line = s + ';' + line;
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
				}
			} else {
				line = "[MISSING KERNEL STACK];" + line;
			}
			line = std::string("----------------;") + line;
			{
				std::string usr_strace("");
				{
					// unsigned deep = 0;
					if (id.usid >= 0) {
						bpf_map_lookup_elem(trace_fd, &id.usid, ip);
						std::string *s = 0, symbol;
						elf_file file;
						for (auto p : ip) {
							if (!p) {
								break;
							}
							sym.reset(p);

							if (g_symbol_parser.find_symbol_in_cache(id.pid, p, symbol)) {
								s = &symbol;
								usr_strace = *s + ';' + usr_strace;
							} else if (g_symbol_parser.get_symbol_info(id.pid, sym, file) &&
									 g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid)) {
								usr_strace = sym.name + ';' + usr_strace;
								g_symbol_parser.putin_symbol_cache(id.pid, p, sym.name);
							} else {
								char a[19];
								sprintf(a, "0x%016llx", p);
								std::string s(a);
								usr_strace = s + ';' + usr_strace;
								g_symbol_parser.putin_symbol_cache(id.pid, p, s);
							}
						}
					} else {
						usr_strace = std::string("[MISSING USER STACK];");
					}
				}
				line = usr_strace + line;
			}
			{
				char cmd[COMM_LEN];
				bpf_map_lookup_elem(comm_fd, &id.pid, cmd);
				line = std::string(cmd) + ':' + std::to_string(id.pid) + ';' + line;
			}
			bpf_map_lookup_elem(value_fd, &id, data_buf);
			line += " " + std::to_string(data_value()) + "\n";
			tex << line;
		}
		std::string tex_s = tex.str();
		FILE *fp = 0;

		fp = fopen("flatex.log", "w");
		CHECK_ERR(!fp, "Failed to save flame text");
		fwrite(tex_s.c_str(), sizeof(char), tex_s.size(), fp);
		fclose(fp);
		fp = popen("flamegraph.pl --cp > flame.svg", "w");
		CHECK_ERR(!fp, "Failed to draw flame graph");
		fwrite(tex_s.c_str(), sizeof(char), tex_s.size(), fp);
		pclose(fp);
		printf("complete\n");
		return 0;
	}

	/// @brief 将表中的栈数据保存为json文件
	/// @param  无
	/// @return 表未成功打开则返回负数
	int data_save(void)
	{
		printf("saving...\n");
		CHECK_ERR(comm_fd < 0, "comm map open failure");
		CHECK_ERR(tgid_fd < 0, "tgid map open failure");
		CHECK_ERR(value_fd < 0, "count map open failure");
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
			if (!ajson.HasMember(tgid_c))
				ajson.AddKeyAndValue(tgid_c, rapidjson::kObjectType);

			std::string pid_s = std::to_string(pid);
			const char *pid_c = pid_s.c_str();
			ajson[tgid_c].AddKeyAndValue(pid_c, rapidjson::kObjectType);

			ajson[tgid_c][pid_c].AddStringAndValue("stacks", rapidjson::kObjectType);

			comm cmd;
			bpf_map_lookup_elem(comm_fd, &pid, &cmd);
			ajson[tgid_c][pid_c].AddStringAndValue("name", cmd.str, alc);
			pidtgid_map[pid] = tgid;
		}

		auto D = sortD();
		for (auto id = D->rbegin(); id != D->rend(); ++id)
		{
			rapidjson::Value *trace;
			{
				rapidjson::Value *stacks;
				{
					std::string tgid_s = std::to_string(pidtgid_map[id->pid]);
					std::string pid_s = std::to_string(id->pid);
					stacks = &(ajson[tgid_s.c_str()][pid_s.c_str()]["stacks"]);
				}
				const char *sid_c;
				{
					auto sid = std::to_string(id->usid) + "," + std::to_string(id->ksid);
					sid_c = sid.c_str();
				}
				stacks->AddKeyAndValue(sid_c, rapidjson::kObjectType);
				(*stacks)[sid_c].AddStringAndValue("count", id->val);
				(*stacks)[sid_c].AddStringAndValue("trace", rapidjson::kArrayType);
				trace = &((*stacks)[sid_c]["trace"]);
			}
			// symbolize
			symbol sym;
			__u64 ip[MAX_STACKS];
			if (id->ksid >= 0)
			{
				bpf_map_lookup_elem(trace_fd, &id->ksid, ip);
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
						trace->PushString(s.c_str());
					}
					else
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string s(a);
						trace->PushString(a);
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
				}
			}
			else
				trace->PushString("[MISSING KERNEL STACK]");
			trace->PushString("----------------");
			if (id->usid >= 0)
			{
				std::string symbol;
				elf_file file;
				bpf_map_lookup_elem(trace_fd, &id->usid, ip);
				for (auto p : ip)
				{
					if (!p)
						break;
					sym.reset(p);
					std::string *s = NULL;
					if (g_symbol_parser.find_symbol_in_cache(id->pid, p, symbol))
					{
						s = &symbol;
						unsigned offset = p - sym.start;
						char offs[20];
						sprintf(offs, " +0x%x", offset);
						*s = *s + std::string(offs);
						trace->PushString(s->c_str());
					}
					else
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string addr_s(a);
						trace->PushString(a);
					}
				}
			}
			else
				trace->PushString("[MISSING USER STACK]");
		}
		delete D;

		FILE *fp = fopen("stack_count.json", "w");
		char writeBuffer[65536];
		rapidjson::FileWriteStream os(fp, writeBuffer, sizeof(writeBuffer));
		rapidjson::Writer<rapidjson::FileWriteStream> writer(os);
		ajson.Accept(writer);
		fclose(fp);
		return 0;
	};

	/// @brief 一个执行ebpf程序的总流程
	/// @param  无
	/// @return 成功则返回0，失败返回负数
	int test(int time) {
		do {
			if (env::command.length()) {
				if (exec_command()) {
					break;
				}
			}
			if (signal(SIGINT, __handler) == SIG_ERR) {
				break;
			}
			if (load()) {
				break;
			}
			if (attach()) {
				break;
			}
			if (env::command.length()) {
				if (activate_child()) {
					break;
				}
			}
			if (env::command.length()) {
				if (signal(SIGCHLD, __handler) == SIG_ERR) {
					break;
				}
			}
			log(time);
		} while (false);
		detach();
		if (env::fla || env::d_mode == FLAME_OUTPUT) {
			err = flame_save();
		} else {
			err = data_save();
		}
		unload();
		if (env::command.length()) {
			clear_child();
		}
		return err;
	};
};

class on_cpu_loader : public bpf_loader {
protected:
	int *pefds, num_cpus, num_online_cpus;
	unsigned long long freq;
	struct perf_event_attr attr;
	struct on_cpu_count_bpf *skel;
	struct bpf_link **links;
	bool *online_mask;
	const char *online_cpus_file;

	std::string data_str(uint64_t f) override { 
		return "counts:" + std::to_string(f); 
	};

public:
	on_cpu_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k, unsigned long long f = env::freq) : bpf_loader(p, c, u, k), freq(f) {
		online_mask = NULL;
		online_cpus_file = "/sys/devices/system/cpu/online";
		err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
		CHECK_ERR_EXIT(err, "Fail to get online CPU numbers");
		num_cpus = libbpf_num_possible_cpus();
		CHECK_ERR_EXIT(num_cpus <= 0, "Fail to get the number of processors");

		pefds = (int *)malloc(num_cpus * sizeof(int));
		for (int i = 0; i < num_cpus; i++) {
			pefds[i] = -1;
		}
		links = (struct bpf_link **)calloc(num_cpus, sizeof(struct bpf_link *));
		attr = {
			.type = PERF_TYPE_SOFTWARE, // hardware event can't be used
			.size = sizeof(attr),
			.config = PERF_COUNT_SW_CPU_CLOCK,
			.sample_freq = freq,
			.inherit = 1,
			.freq = 1, // use freq instead of period
		};
		skel = 0;
	};

	int load(void) override {
		FILE *fp = popen("cat /proc/kallsyms | grep \" avenrun\"", "r");
		CHECK_ERR(!fp, "Failed to draw flame graph");
		unsigned long *load_a;
		fscanf(fp, "%p", &load_a);
		pclose(fp);
		StackProgLoadOpen(
			on_cpu_count,
			psid_count,
			skel->bss->load_a = load_a,
			skel->bss->u = ustack,
			skel->bss->k = kstack
		)
		return 0;
	};

	int attach(void) override {
		for (int cpu = 0; cpu < num_cpus; cpu++) {
			/* skip offline/not present CPUs */
			if (cpu >= num_online_cpus || !online_mask[cpu]) {
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

	void detach(void) override {
		if (links) {
			for (int cpu = 0; cpu < num_cpus; cpu++) {
				bpf_link__destroy(links[cpu]);
			}
			free(links);
		}
		if (pefds)
		{
			for (int i = 0; i < num_cpus; i++) {
				if (pefds[i] >= 0) {
					close(pefds[i]);
				}
			}
			free(pefds);
		}
	}

	void unload(void) override {
		if (skel) {
			on_cpu_count_bpf__destroy(skel);
		}
		skel = 0;
	}
};

class off_cpu_loader : public bpf_loader {
protected:
	struct off_cpu_count_bpf *skel;

	std::string data_str(uint64_t f) override { 
		return "time(ms):" + std::to_string(f); 
	};

public:
	off_cpu_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k) {
		skel = 0;
	};

	int load(void) override {
		StackProgLoadOpen(
			off_cpu_count,
			psid_count,
			skel->bss->apid = pid,
			skel->bss->u = ustack,
			skel->bss->k = kstack
		)
		return 0;
	};

	int attach(void) override {
		err = bpf_attach(off_cpu_count, skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};

	void detach(void) override {
		if (skel) {
			off_cpu_count_bpf__detach(skel);
		}
	};

	void unload(void) override {
		if (skel) {
			off_cpu_count_bpf__destroy(skel);
		}
		skel = 0;
	};
};

class mem_loader : public bpf_loader {
protected:
	struct mem_count_bpf *skel;
	char *object;

	std::string data_str(uint64_t f) override { return "size(Byte):" + std::to_string(f); };

public:
	mem_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k, char *e = env::object) : bpf_loader(p, c, u, k), object(e) {
		skel = 0;
	};

	int load(void) override {
		StackProgLoadOpen(
			mem_count,
			psid_count,
			skel->bss->u = ustack,
			skel->bss->apid = pid
		)
		return 0;
	};

	int attach(void) override {
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

		err = mem_count_bpf__attach(skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};

	void detach(void) override {
		if (skel->links.free_enter) {
			bpf_link__destroy(skel->links.free_enter);
		}
		if (skel->links.malloc_exit) {
			bpf_link__destroy(skel->links.malloc_exit);
		}
		if (skel->links.malloc_enter) {
			bpf_link__destroy(skel->links.malloc_enter);
		}
	};

	void unload(void) override {
		if (skel) {
			mem_count_bpf__destroy(skel);
		}
		skel = 0;
	};
};

class io_loader : public bpf_loader {
protected:
	struct io_count_bpf *skel;
	DATA d = env::data;
	std::string data_str(uint64_t f) override {
		std::string p;
		if (d == SIZE) {
			p = "size(B):";
		} else if (d == COUNT) {
			p = "counts:";
		} else {
			p = "(size/counts):";
		}
		return p + std::to_string(f);
	};

public:
	io_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k) {
		skel = 0;
		// in_count = cot;
		delete (uint64_t *)data_buf;
		data_buf = new io_tuple{0};
	};
	
	int load(void) override {
		StackProgLoadOpen(io_count, psid_count, {
			skel->bss->apid = pid;
			skel->bss->u = ustack;
			skel->bss->k = kstack;
			// skel->bss->cot = in_count;
		});
		return 0;
	};
	
	int attach(void) override {
		err = bpf_attach(io_count, skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	
	void detach(void) override {
		if (skel)
			io_count_bpf__detach(skel);
	};
	
	void unload(void) override {
		if (skel)
			io_count_bpf__destroy(skel);
		skel = 0;
	};

	uint64_t data_value() override {
		io_tuple *p = (io_tuple *)data_buf;
		// return p->expect - p->truth;
		if (env::data == AVE)
			return p->size / p->count;
		else if (env::data == SIZE)
			return p->size;
		else
			return p->count;
	};

	~io_loader() override {
		delete (io_tuple *)data_buf;
	};
};

class pre_loader : public bpf_loader {
protected:
	struct pre_count_bpf *skel;

	std::string data_str(uint64_t f) override {
		return "rest_pages:" + std::to_string(f); 
	};

public:
	pre_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k) {
		skel = 0;
		delete (uint64_t *)data_buf;
		data_buf = new tuple{0};
	};
	int load(void) override {
		StackProgLoadOpen(
			pre_count, 
			psid_util, 
			{
				skel->bss->apid = pid;
				skel->bss->u = ustack;
				skel->bss->k = kstack;
			}
		);
		return 0;
	};
	int attach(void) override {
		err = pre_count_bpf__attach(skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void) override
	{
		if (skel) {
			pre_count_bpf__detach(skel);
		}
	};
	void unload(void) override {
		if (skel) {
			pre_count_bpf__destroy(skel);
		}
		skel = 0;
	};

	uint64_t data_value() override {
		tuple *p = (tuple *)data_buf;
		return p->expect - p->truth;
	};

	~pre_loader() override {
		delete (tuple *)data_buf;
	}

};

typedef bpf_loader *(*bpf_load)();

int main(int argc, char *argv[]) {
	auto oncpu_mod = (
		clipp::command("on-cpu").set(env::mod, MOD_ON_CPU),
		clipp::option("-F", "--frequency") & clipp::value("sampling frequency", env::freq) % "sampling at a set frequency"
	) % "sample the call stacks of on-cpu processes";

	auto offcpu_mod = (
		clipp::command("off-cpu").set(env::mod, MOD_OFF_CPU)
	) % "sample the call stacks of off-cpu processes";
	
	auto mem_mod = (
		clipp::command("mem").set(env::mod, MOD_MEM)
	) % "sample the memory usage of call stacks";
	
	auto io_mod = (
		clipp::command("io").set(env::mod, MOD_IO),
		(clipp::option("--mod") & (
			clipp::option("count").set(env::data, COUNT) % "Counting the number of I/O operations" |
			clipp::option("ave").set(env::data, AVE) % "Counting the ave of I/O operations" |
			clipp::option("size").set(env::data, SIZE) % "Counting the size of I/O operations"
		)) % "set the statistic mod"
	) % "sample the IO data volume of call stacks";
	
	auto pre_mod = (
		clipp::command("ra").set(env::mod, MOD_RA)
	) % "sample the readahead hit rate of call stacks";
	
	auto opti = (
		clipp::option("-f", "--flame-graph").set(env::fla) % "save in flame.svg instead of stack_count.json",
		(
			((clipp::option("-p", "--pid") & clipp::value("pid of sampled process", env::pid)) % "set pid of process to monitor") |
			((clipp::option("-c", "--command") & clipp::value("to be sampled command to run", env::command)) % "set command for monitoring the whole life")
		),
		clipp::option("-U", "--user-stack-only").set(env::k, false) % "only sample user stacks",
		clipp::option("-K", "--kernel-stack-only").set(env::u, false) % "only sample kernel stacks",
		(clipp::option("-m", "--max-value") & clipp::value("max threshold of sampled value", env::max)) % "set the max threshold of sampled value",
		(clipp::option("-n", "--min-value") & clipp::value("min threshold of sampled value", env::min)) % "set the min threshold of sampled value",
		(clipp::option("-d", "--delay") & clipp::value("delay time to output", env::delay)) % "set the interval to output",
		(
			clipp::option("-r", "--realtime-draw").set(env::d_mode, FLAME_OUTPUT) % "draw flame graph realtimely" |
			clipp::option("-l", "--realtime-list").set(env::d_mode, LIST_OUTPUT) % "output in console"
		) % "display mode (default none)",
		clipp::opt_value("simpling time", env::run_time) % "set the total simpling time",
		clipp::option("-D", "--delta").set(env::clear, true) % "show delta in the interval instead of total count"
	);
	
	auto cli = (
		(oncpu_mod | offcpu_mod | mem_mod | io_mod | pre_mod),
		opti,
		clipp::option("-v", "--version").call([] {
			std::cout << "verion 1.0\n\n"; 
		}) % "show version"
	) % "statistic call trace relate with some metrics";
	
	if (!clipp::parse(argc, argv, cli)) {
		std::cout << clipp::make_man_page(cli, argv[0]) << '\n';
		return 0;
	}
	
	bpf_load arr[] = {
		[]() -> bpf_loader *{ return new on_cpu_loader(); },
		[]() -> bpf_loader *{ return new off_cpu_loader(); },
		[]() -> bpf_loader *{ return new mem_loader(); },
		[]() -> bpf_loader *{ return new io_loader(); },
		[]() -> bpf_loader *{ return new pre_loader(); },
	};

	return arr[env::mod]()->test(env::run_time);
}