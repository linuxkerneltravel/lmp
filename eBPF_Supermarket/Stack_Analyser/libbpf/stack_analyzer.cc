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
extern "C"
{
#endif

#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/eventfd.h>
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

/// @brief  printing help information
/// @param progname progname printed in the help info
static void show_help(const char *progname)
{
	printf("Usage: %s [-F <frequency>=49] [-p <pid>=-1] [-T <time>=INT_MAX] [-m <0 on cpu|1 off cpu|2 mem|3 io|4 preread>=0] "
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

/// @brief 初始化eventfd
/// @param fd 事件描述符
/// @return 成功返回0，失败返回-1
int event_init(int *fd)
{
	CHECK_ERR(!fd, "pointer to fd is null");
	const int tmp_fd = eventfd(0, EFD_CLOEXEC);
	CHECK_ERR(tmp_fd < 0, "failed to create event fd");
	*fd = tmp_fd;
	return 0;
}

/// @brief 等待事件
/// @param fd 事件描述符
/// @param expected_event 期望事件
/// @return 成功返回0，失败返回-1
int event_wait(int fd, uint64_t expected_event)
{
	uint64_t event = 0;
	const ssize_t bytes = read(fd, &event, sizeof(event));

	CHECK_ERR(bytes < 0, "failed to read from fd")
	else CHECK_ERR(bytes != sizeof(event), "read unexpected size");

	CHECK_ERR(event != expected_event, "read event %lu, expected %lu", event, expected_event);

	return 0;
}

pid_t fork_sync_exec(const char *command, int fd)
{
	// auto cmd = std::string(command) + " > /dev/null";
	const pid_t pid = fork();
	sigset_t ss, oss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigprocmask(SIG_BLOCK, &ss, &oss);
	switch (pid)
	{
	case -1:
		perror("failed to create child process");
		break;
	case 0:
		CHECK_ERR_EXIT(event_wait(fd, (uint64_t)1), "failed to wait on event");
		printf("received go event. executing child command\n");
		CHECK_ERR_EXIT(execl("/bin/bash", "bash", "-c", command, NULL), "failed to execute child command");
		break;
	default:
		printf("child created with pid: %d\n", pid);
		sigprocmask(SIG_SETMASK, &oss, NULL);
		break;
	}
	return pid;
}

/// @brief 更新事件
/// @param fd 事件描述符
/// @param event 通知的事件
/// @return 失败返回-1，成功返回0
int event_notify(int fd, uint64_t event)
{
	const ssize_t bytes = write(fd, &event, sizeof(event));
	CHECK_ERR(bytes < 0, "failed to write to fd")
	else CHECK_ERR(bytes != sizeof(event), "attempted to write %zu bytes, wrote %zd bytes", sizeof(event), bytes);
	return 0;
}

namespace env
{
	int pid = -1;												  /*pid filter*/
	int cpu = -1;												  /*cpu index*/
	int run_time = __INT_MAX__;									  /*run time*/
	int freq = 49;												  /*simple frequency*/
	MOD mod = MOD_ON_CPU;										  /*mod setting*/
	bool u = true;												  /*user stack setting*/
	bool k = true;												  /*kernel stack setting*/
	bool fla = false;											  /*flame graph instead of json*/
	char *object = (char *)"/usr/lib/x86_64-linux-gnu/libc.so.6"; /*executable binary file for uprobe*/
	static volatile sig_atomic_t exiting, child_exited;			  /*exiting flag*/
	static int child_exec_event_fd = -1;
	std::string command = "";
}

void __handler(int signo)
{
	// printf("sig %d %d\n", signo, kill(env::pid, 0));
	if (signo == SIGCHLD && kill(env::pid, 0))
	{
		env::child_exited = 1;
	}
	env::exiting = 1;
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
	void *data_buf;

/// @brief 获取epbf程序中指定表的文件描述符
/// @param name 表的名字
#define OPEN_MAP(name) bpf_map__fd(skel->maps.name)

/// @brief 获取所有表的文件描述符
#define OPEN_ALL_MAP(value_map_name)     \
	value_fd = OPEN_MAP(value_map_name); \
	tgid_fd = OPEN_MAP(pid_tgid);        \
	comm_fd = OPEN_MAP(pid_comm);        \
	trace_fd = OPEN_MAP(stack_trace);

/// @brief 加载、初始化参数并打开指定类型的ebpf程序
/// @param name ebpf程序的类型名
/// @param ... 一些ebpf程序全局变量初始化语句
/// @note 失败会使上层函数返回-1
#define LO(name, val_map_name, ...)                \
	skel = name##_bpf__open();                     \
	CHECK_ERR(!skel, "Fail to open BPF skeleton"); \
	skel->bss->min = min;                          \
	skel->bss->max = max;                          \
	__VA_ARGS__;                                   \
	err = name##_bpf__load(skel);                  \
	CHECK_ERR(err, "Fail to load BPF skeleton");   \
	OPEN_ALL_MAP(val_map_name)

/// @class rapidjson::Value
/// @brief 添加字符串常量键和任意值，值可使用内存分配器
/// @param k 设置为键的字符串常量
/// @param ... 对应值，可使用内存分配器
#define CKV(k, ...)                                 \
	AddMember(k,                                    \
			  rapidjson::Value(__VA_ARGS__).Move(), \
			  alc)

/// @class rapidjson::Value
/// @brief 添加需要分配内存的变量字符串键和值，值可使用内存分配器
/// @param k 设置为键的字符串变量
/// @param ... 对应值，可使用内存分配器
#define KV(k, ...)                                  \
	AddMember(rapidjson::Value(k, alc).Move(),      \
			  rapidjson::Value(__VA_ARGS__).Move(), \
			  alc)

/// @class rapidjson::Value::kArray
/// @brief 添加字符串变量
/// @param v 要添加的字符串变量
#define PV(v) PushBack(rapidjson::Value(v, alc), alc)

	virtual double data_value()
	{
		return *(uint64_t *)data_buf * 1.;
	};

	class pksid_val
	{
	public:
		int32_t pid, ksid, usid;
		double val;
		pksid_val(int32_t p, int32_t k, int32_t u, double v)
		{
			pid = p;
			ksid = k;
			usid = u;
			val = v;
		};

		bool operator<(const pksid_val b) { return val < b.val; };
	};

	std::vector<pksid_val> *sortD()
	{
		if (value_fd < 0)
			return NULL;
		std::vector<pksid_val> *D = new std::vector<pksid_val>();
		for (psid prev = {0}, id; !bpf_map_get_next_key(value_fd, &prev, &id); prev = id)
		{
			bpf_map_lookup_elem(value_fd, &id, data_buf);
			pksid_val d(id.pid, id.ksid, id.usid, data_value());
			D->insert(std::lower_bound(D->begin(), D->end(), d), d);
		}
		return D;
	};

	/// @brief 每隔5s输出计数表中的栈及数量
	/// @param time 输出的持续时间
	/// @return 返回被强制退出时的剩余时间，计数表未打开则返回-1
	int log(int time)
	{
		CHECK_ERR(value_fd < 0, "count map open failure");
		/*for traverse map*/
		for (; !env::exiting && time > 0 && (env::pid < 0 || !kill(env::pid, 0)); time -= 5)
		{
			printf("---------%d---------\n", value_fd);
			sleep(5);
			auto D = sortD();

			for (auto id : *D)
			{
				__u64 ip[MAX_STACKS];
				if (id.usid >= 0)
				{
					bpf_map_lookup_elem(trace_fd, &id.usid, ip);
					std::string symbol;
					struct symbol sym;
					elf_file file;
					for (auto p : ip)
					{
						if (!p)
							break;
						sym.reset(p);

						if (g_symbol_parser.find_symbol_in_cache(id.pid, p, symbol))
							continue;
						if (g_symbol_parser.get_symbol_info(id.pid, sym, file) &&
							g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid))
							g_symbol_parser.putin_symbol_cache(id.pid, p, sym.name);
					}
				}
				printf("%6d\t(%6d,%6d)\t%.2lf\n", id.pid, id.ksid, id.usid, id.val);
			}
			delete D;
		};
		return time;
	};

	int exec_command()
	{
		// if specific userspace program was specified,
		// create the child process and use an eventfd to synchronize the call to exec()
		CHECK_ERR(env::pid >= 0, "cannot specify both command and pid");
		CHECK_ERR(event_init(&env::child_exec_event_fd), "failed to init child event");
		env::pid = pid = fork_sync_exec(env::command.c_str(), env::child_exec_event_fd);
		CHECK_ERR(pid < 0, "failed to spawn child process");
		return 0;
	};

	int activate_child()
	{
		int ret = event_notify(env::child_exec_event_fd, 1);
		CHECK_ERR(ret, "failed to notify child to perform exec");
		return 0;
	};

	int clear_child()
	{
		if (!env::child_exited)
		{
			CHECK_ERR(kill(env::pid, SIGTERM), "failed to signal child process");
			printf("signaled child process\n");
		}
		CHECK_ERR(waitpid(env::pid, NULL, 0) < 0, "failed to reap child process");
		printf("reaped child process\n");
		return 0;
	};

public:
	bpf_loader(
		int p = env::pid,
		int c = env::cpu,
		bool u = env::u,
		bool k = env::k,
		uint64_t n = 1ull,
		uint64_t m = UINT64_MAX) : pid(p), cpu(c), ustack(u), kstack(k), min(n), max(m)
	{
		value_fd = tgid_fd = comm_fd = trace_fd = -1;
		err = 0;
		data_buf = new uint64_t(0);
	};

	virtual ~bpf_loader()
	{
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
		int max_deep = 0;
		for (psid prev = {}, key; !bpf_map_get_next_key(value_fd, &prev, &key); prev = key)
		{
			__u64 ip[MAX_STACKS];
			bpf_map_lookup_elem(trace_fd, &key.usid, ip);
			int deep = 0;
			for (int i = 0; i < MAX_STACKS && ip[i]; i++)
				deep++;
			if (max_deep < deep)
				max_deep = deep;
		}
		std::ostringstream tex("");
		for (psid prev = {}, id; !bpf_map_get_next_key(value_fd, &prev, &id); prev = id)
		{
			std::string line("");
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
						line = sym.name + ';' + line;
					else
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string s(a);
						line = s + ';' + line;
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
				}
			}
			else
				line = "[MISSING KERNEL STACK];" + line;
			line = std::string("----------------;") + line;
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
							{
								s = &sym.name;
						g_symbol_parser.putin_symbol_cache(id.pid, p, sym.name);
							}
							else
							{
								char a[19];
								sprintf(a, "0x%016llx", p);
								std::string s(a);
								line = s + ';' + line;
								g_symbol_parser.putin_symbol_cache(pid, p, s);
							}

							deep++;
						}
					}
					else
					{
						line = std::string("[MISSING USER STACK];") + line;
						deep = 1;
					}
					deep = max_deep - deep;
					for (int i = 0; i < deep; i++)
					{
						line = ".;" + line;
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

		fp = popen("flamegraph.pl > flame.svg", "w");
		CHECK_ERR(!fp, "Failed to draw flame graph");
		// fwrite("", 1, 0, fp);
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
				stacks->KV(sid_c, rapidjson::kObjectType);
				(*stacks)[sid_c].CKV("count", id->val);
				(*stacks)[sid_c].CKV("trace", rapidjson::kArrayType);
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
						trace->PV(s.c_str());
					}
					else
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string s(a);
						trace->PV(a);
						g_symbol_parser.putin_symbol_cache(pid, p, s);
					}
				}
			}
			else
				trace->PV("[MISSING KERNEL STACK]");
			trace->PV("----------------");
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
						trace->PV(s->c_str());
					}
					else
					{
						char a[19];
						sprintf(a, "0x%016llx", p);
						std::string addr_s(a);
						trace->PV(a);
					}
				}
			}
			else
				trace->PV("[MISSING USER STACK]");
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
	int test(int time)
	{
		do
		{
			if (env::command.length())
				if (exec_command())
					break;
			if (signal(SIGINT, __handler) == SIG_ERR)
				break;
			if (load())
				break;
			if (attach())
				break;
			if (env::command.length())
				if (activate_child())
					break;
			if (signal(SIGCHLD, __handler) == SIG_ERR)
				break;
			log(time);
		} while (false);
		detach();
		if (env::fla)
			err = flame_save();
		else
			err = data_save();
		// unload();
		if (env::command.length())
			clear_child();
		return err;
	};
};

class on_cpu_loader : public bpf_loader
{
protected:
	int *pefds, num_cpus, num_online_cpus;
	unsigned long long freq;
	struct perf_event_attr attr;
	struct on_cpu_count_bpf *skel;
	struct bpf_link **links;
	bool *online_mask;
	const char *online_cpus_file;

public:
	on_cpu_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k, unsigned long long f = env::freq) : bpf_loader(p, c, u, k), freq(f)
	{
		online_mask = NULL;
		online_cpus_file = "/sys/devices/system/cpu/online";
		err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
		CHECK_ERR_EXIT(err, "Fail to get online CPU numbers");
		num_cpus = libbpf_num_possible_cpus();
		CHECK_ERR_EXIT(num_cpus <= 0, "Fail to get the number of processors");

		pefds = (int *)malloc(num_cpus * sizeof(int));
		for (int i = 0; i < num_cpus; i++)
		{
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
	int load(void) override
	{
		FILE *fp = popen("cat /proc/kallsyms | grep \" avenrun\"", "r");
		CHECK_ERR(!fp, "Failed to draw flame graph");
		// fwrite("", 1, 0, fp);
		unsigned long *load_a;
		fscanf(fp, "%p", &load_a);
		pclose(fp);
		LO(on_cpu_count,
		   psid_count,
		   skel->bss->load_a = load_a,
		   skel->bss->u = ustack,
		   skel->bss->k = kstack)
		return 0;
	};
	int attach(void) override
	{
		for (int cpu = 0; cpu < num_cpus; cpu++)
		{
			/* skip offline/not present CPUs */
			if (cpu >= num_online_cpus || !online_mask[cpu])
				continue;

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
				bpf_link__destroy(links[cpu]);
			free(links);
		}
		if (pefds)
		{
			for (int i = 0; i < num_cpus; i++)
			{
				if (pefds[i] >= 0)
					close(pefds[i]);
			}
			free(pefds);
		}
	}
	void unload(void) override
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

public:
	off_cpu_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k)
	{
		skel = 0;
	};
	int load(void) override
	{
		LO(off_cpu_count,
		   psid_count,
		   skel->bss->apid = pid,
		   skel->bss->u = ustack,
		   skel->bss->k = kstack)
		return 0;
	};
	int attach(void) override
	{
		err = bpf_attach(off_cpu_count, skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void) override
	{
		if (skel)
			off_cpu_count_bpf__detach(skel);
	};
	void unload(void) override
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
	int load(void) override
	{
		LO(mem_count,
		   psid_count,
		   skel->bss->u = ustack,
		   //    skel->bss->k = kstack,
		   skel->bss->apid = pid)
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

		err = mem_count_bpf__attach(skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void) override
	{
		if (skel->links.free_enter)
			bpf_link__destroy(skel->links.free_enter);
		if (skel->links.malloc_exit)
			bpf_link__destroy(skel->links.malloc_exit);
		if (skel->links.malloc_enter)
			bpf_link__destroy(skel->links.malloc_enter);
	};
	void unload(void) override
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
	int load(void) override
	{
		LO(io_count, psid_count, {
			skel->bss->apid = pid;
			skel->bss->u = ustack;
			skel->bss->k = kstack;
		});
		return 0;
	};
	int attach(void) override
	{
		err = bpf_attach(io_count, skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void) override
	{
		if (skel)
			io_count_bpf__detach(skel);
	};
	void unload(void) override
	{
		if (skel)
			io_count_bpf__destroy(skel);
		skel = 0;
	};
};

class pre_loader : public bpf_loader
{
protected:
	struct pre_count_bpf *skel;

public:
	pre_loader(int p = env::pid, int c = env::cpu, bool u = env::u, bool k = env::k) : bpf_loader(p, c, u, k)
	{
		skel = 0;
		delete (uint64_t *)data_buf;
		data_buf = new tuple{0};
	};
	int load(void) override
	{
		LO(pre_count, psid_util, {
			skel->bss->apid = pid;
			skel->bss->u = ustack;
			skel->bss->k = kstack;
		});
		return 0;
	};
	int attach(void) override
	{
		// auto object = env::object;
		// ATTACH_UPROBE_CHECKED(skel, read, read_enter);
		err = pre_count_bpf__attach(skel);
		CHECK_ERR(err, "Failed to attach BPF skeleton");
		return 0;
	};
	void detach(void) override
	{
		if (skel)
			pre_count_bpf__detach(skel);
	};
	void unload(void) override
	{
		if (skel)
			pre_count_bpf__destroy(skel);
		skel = 0;
	};

	double data_value() override
	{
		tuple *p = (tuple *)data_buf;
		return (p->expect - p->truth) * 1.;
	};

	~pre_loader() override
	{
		delete (tuple *)data_buf;
	}
};

typedef bpf_loader *(*bpf_load)();

int main(int argc, char *argv[])
{
	auto oncpu_mod = (clipp::command("on-cpu").set(env::mod, MOD_ON_CPU) % "sample the call stacks of on-cpu processes",
					  clipp::option("-F", "--frequency") & clipp::value("sampling frequency", env::freq) % "sampling at a set frequency");
	auto offcpu_mod = (clipp::command("off-cpu").set(env::mod, MOD_OFF_CPU) % "sample the call stacks of off-cpu processes");
	auto mem_mod = (clipp::command("mem").set(env::mod, MOD_MEM) % "sample the memory usage of call stacks");
	auto io_mod = (clipp::command("io").set(env::mod, MOD_IO) % "sample the IO data volume of call stacks");
	auto pre_mod = (clipp::command("ra").set(env::mod, MOD_RA) % "sample the readahead hit rate of call stacks");
	auto opti = (clipp::option("-f", "--flame-graph").set(env::fla),
				 (
					 clipp::option("-p", "--pid") & clipp::value("set the pid of sampled process", env::pid)) |
					 (clipp::option("-c", "--command") & clipp::value("set the sampled command to run", env::command)),
				 clipp::option("-U", "--user-stack-only").set(env::k, false),
				 clipp::option("-K", "--kernel-stack-only").set(env::u, false),
				 clipp::opt_value("simpling time", env::run_time));
	auto cli = ((oncpu_mod | offcpu_mod | mem_mod | io_mod | pre_mod),
				opti,
				clipp::option("-v", "--version").call([]
													  { std::cout << "verion 1.0\n\n"; }) %
					"show version");
	if (!clipp::parse(argc, argv, cli))
	{
		std::cout << clipp::make_man_page(cli, argv[0]) << '\n';
		return 0;
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
		[]() -> bpf_loader *
		{ return new pre_loader(); },
	};
	return arr[env::mod]()->test(env::run_time);
}