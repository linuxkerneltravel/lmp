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
// 主函数，负责参数解析，管理被监控命令对应的进程，数据输出

#include <signal.h>
#include <iostream>
#include <poll.h>
#include <fcntl.h>
#include <time.h>

#include "bpf_wapper/on_cpu.h"
#include "bpf_wapper/llc_stat.h"
#include "bpf_wapper/off_cpu.h"
#include "bpf_wapper/memleak.h"
#include "bpf_wapper/io.h"
#include "bpf_wapper/readahead.h"
#include "bpf_wapper/probe.h"
#include "user.h"
#include "clipp.h"
#include "cgroup.h"
#include "trace.h"

bool timeout = false;
std::vector<StackCollector *> StackCollectorList;
void end_handle(void);

namespace MainConfig
{
    uint64_t run_time = -1; // 运行时间
    unsigned delay = 5;     // 设置输出间隔
    std::string command = "";
    uint32_t target_tgid = 0;
    uint64_t target_cgroup = 0;
    std::string trigger = "";    // 触发器
    std::string trig_event = ""; // 触发事件
    uint32_t top = 10;
    uint32_t freq = 49;
    bool trace_user = false;
    bool trace_kernel = false;
}

int main(int argc, char *argv[])
{
    uint64_t stop_time = -1;
    clipp::man_page man_page;
    clipp::group cli;
    {
        uint64_t IntTmp;
        std::string StrTmp;
        auto OnCpuOption = (clipp::option("on_cpu")
                                .call([]
                                      { StackCollectorList.push_back(new OnCPUStackCollector()); }) %
                            COLLECTOR_INFO("on-cpu"));

        auto OffCpuOption = clipp::option("off_cpu")
                                .call([]
                                      { StackCollectorList.push_back(new OffCPUStackCollector()); }) %
                            COLLECTOR_INFO("off-cpu");

        auto MemleakOption = (clipp::option("memleak")
                                  .call([]
                                        { StackCollectorList.push_back(new MemleakStackCollector()); }) %
                              COLLECTOR_INFO("memleak")) &
                             (clipp::option("-W")
                                  .call([]
                                        { static_cast<MemleakStackCollector *>(StackCollectorList.back())
                                              ->wa_missing_free = true; }) %
                              "Free when missing in kernel to alleviate misjudgments");

        auto IOOption = clipp::option("io")
                            .call([]
                                  { StackCollectorList.push_back(new IOStackCollector()); }) %
                        COLLECTOR_INFO("io");

        auto ReadaheadOption = clipp::option("readahead")
                                   .call([]
                                         { StackCollectorList.push_back(new ReadaheadStackCollector()); }) %
                               COLLECTOR_INFO("readahead");

        auto LlcStatOption = clipp::option("llc_stat").call([]
                                                            { StackCollectorList.push_back(new LlcStatStackCollector()); }) %
                                 COLLECTOR_INFO("llc_stat") &
                             ((clipp::option("-P") &
                               clipp::value("period", IntTmp)
                                   .call([IntTmp]
                                         { static_cast<LlcStatStackCollector *>(StackCollectorList.back())
                                               ->setScale(IntTmp); })) %
                              "Set sampling period; default is 100");

        auto ProbeOption = clipp::option("probe")
                                   .call([]
                                         { StackCollectorList.push_back(new ProbeStackCollector()); }) %
                               COLLECTOR_INFO("probe") &
                           (clipp::value("probe", StrTmp)
                                .call([&StrTmp]
                                      { static_cast<ProbeStackCollector *>(StackCollectorList.back())
                                            ->setScale(StrTmp); }) %
                            "Set the probe string; specific use is:\n"
                            "<func> | p::<func>             -- probe a kernel function;\n"
                            "<lib>:<func> | p:<lib>:<func>  -- probe a user-space function in the library 'lib';\n"
                            "t:<class>:<func>               -- probe a kernel tracepoint;\n"
                            "u:<lib>:<probe>                -- probe a USDT tracepoint");

        auto MainOption = _GREEN "Some overall options" _RE %
                          ((
                               ((clipp::option("-g") &
                                 clipp::value("cgroup path", StrTmp)
                                     .call([&StrTmp]
                                           { MainConfig::target_cgroup = get_cgroupid(StrTmp.c_str()); printf("Trace cgroup %ld\n", MainConfig::target_cgroup); })) %
                                "Set the cgroup of the process to be tracked; default is -1, which keeps track of all cgroups") |
                               ((clipp::option("-p") &
                                 clipp::value("pid", MainConfig::target_tgid)) %
                                "Set the pid of the process to be tracked; default is -1, which keeps track of all processes") |
                               ((clipp::option("-c") &
                                 clipp::value("command", MainConfig::command)) %
                                "Set the command to be run and sampled; defaults is none")),
                           (clipp::option("-o") &
                            clipp::value("top", MainConfig::top)) %
                               "Set the top number; default is 10",
                           (clipp::option("-f") &
                            clipp::value("freq", MainConfig::freq)) %
                               "Set sampling frequency, 0 for close; default is 49",
                           (clipp::option("-i") &
                            clipp::value("interval", MainConfig::delay)) %
                               "Set the output delay time (seconds); default is 5",
                           (clipp::option("-d") &
                            clipp::value("duration", MainConfig::run_time)
                                .call([&stop_time]
                                      { stop_time = time(NULL) + MainConfig::run_time; })) %
                               "Set the total sampling time; default is __INT_MAX__",
                           (clipp::option("-u")
                                    .call([]
                                          { MainConfig::trace_user = true; }) %
                                "Sample user stacks",
                            clipp::option("-k")
                                    .call([]
                                          { MainConfig::trace_kernel = true; }) %
                                "Sample kernel stacks"),
                           (clipp::option("-T") &
                            ((clipp::required("cpu").set(MainConfig::trigger) |
                              clipp::required("memory").set(MainConfig::trigger) |
                              clipp::required("io").set(MainConfig::trigger)) &
                             clipp::value("event", MainConfig::trig_event))) %
                               "Set a trigger for monitoring. For example, " _ERED "-T cpu \"some 150000 100000\" " _RE
                               "means triggers when cpu partial stall "
                               "with 1s tracking window size * and 150ms threshold.");

        auto Info = _GREEN "Information of the application" _RE %
                    ((clipp::option("-v", "--version")
                          .call([]
                                { std::cout << "verion 2.0\n\n"; }) %
                      "Show version"),
                     (clipp::option("-h", "--help")
                          .call([&man_page]
                                { std::cout << man_page << std::endl; exit(0); }) %
                      "Show man page"));

        cli = (OnCpuOption,
               OffCpuOption,
               MemleakOption,
               IOOption,
               ReadaheadOption,
               LlcStatOption,
               clipp::repeatable(ProbeOption),
               MainOption,
               Info);
    }
    {
        auto fmt = clipp::doc_formatting{}
                       .first_column(3)
                       .doc_column(25)
                       .last_column(128);
        man_page = clipp::make_man_page(cli, argv[0], fmt)
                       .prepend_section("DESCRIPTION", _RED "Count the function call stack associated with some metric.\n" _RE BANNER)
                       .append_section("LICENSE", _RED "Apache Licence 2.0" _RE);
    }
    if (!clipp::parse(argc, argv, cli))
    {
        std::cerr << man_page << std::endl;
        return -1;
    }
    if (StackCollectorList.size() == 0)
    {
        printf(_ERED "At least one collector needs to be added.\n" _RE);
        return -1;
    }

    fprintf(stderr, BANNER "\n");

    uint64_t eventbuff = 1;
    int child_exec_event_fd = eventfd(0, EFD_CLOEXEC);
    CHECK_ERR_RN1(child_exec_event_fd < 0, "failed to create event fd");
    if (MainConfig::command.length())
    {
        MainConfig::target_tgid = fork();
        switch (MainConfig::target_tgid)
        {
        case (uint32_t)-1:
        {
            CHECK_ERR_RN1(true, "Command create failed.");
        }
        case 0:
        {
            const auto bytes = read(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
            CHECK_ERR_RN1(bytes < 0, "Failed to read from fd %ld", bytes)
            else CHECK_ERR_RN1(bytes != sizeof(eventbuff), "Read unexpected size %ld", bytes);
            printf("child exec %s\n", MainConfig::command.c_str());
            CHECK_ERR(exit(-1), execl("/bin/bash", "bash", "-c", MainConfig::command.c_str(), NULL), "failed to execute child command");
            break;
        }
        default:
        {
            printf("Create child %d\n", MainConfig::target_tgid);
            break;
        }
        }
    }

    ksyms = ksyms__load();
    if (!ksyms)
    {
        fprintf(stderr, "failed to load kallsyms\n");
        exit(1);
    }
    syms_cache = syms_cache__new(0);
    if (!syms_cache)
    {
        fprintf(stderr, "failed to create syms_cache\n");
        exit(1);
    }
    
    for (auto Item = StackCollectorList.begin(); Item != StackCollectorList.end();)
    {
        fprintf(stderr, _RED "Attach collecotor%d %s.\n" _RE,
                (int)(Item - StackCollectorList.begin()) + 1, (*Item)->getName());
        (*Item)->tgid = MainConfig::target_tgid;
        (*Item)->cgroup = MainConfig::target_cgroup;
        (*Item)->top = MainConfig::top;
        (*Item)->freq = MainConfig::freq;
        (*Item)->kstack = MainConfig::trace_kernel;
        (*Item)->ustack = MainConfig::trace_user;
        if ((*Item)->ready())
            goto err;
        Item++;
        continue;
    err:
        fprintf(stderr, _ERED "Collector %s err.\n" _RE, (*Item)->getName());
        (*Item)->finish();
        Item = StackCollectorList.erase(Item);
    }

    if (StackCollectorList.size() == 0)
    {
        fprintf(stderr, _ERED "No collecter to run.\n" _RE);
        return -1;
    }

    if (MainConfig::command.length())
    {
        fprintf(stderr, _GREEN "Wake up child.\n" _RE);
        write(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
    }

    atexit(end_handle);
    signal(SIGINT, [](int)
           { exit(EXIT_SUCCESS); });

    struct pollfd fds = {.fd = -1};
    if (MainConfig::trigger != "" && MainConfig::trig_event != "")
    {
        auto path = MainConfig::trigger.c_str();
        auto trig = MainConfig::trig_event.c_str();

        fds.fd = open(path, O_RDWR | O_NONBLOCK);
        CHECK_ERR_RN1(fds.fd < 0, "%s open error", path);
        fds.events = POLLPRI;
        CHECK_ERR_RN1(write(fds.fd, trig, strlen(trig) + 1) < 0, "%s write error", path);
        fprintf(stderr, _RED "Waiting for events...\n" _RE);
    }
    fprintf(stderr, _RED "Running for %lus or Hit Ctrl-C to end.\n" _RE, MainConfig::run_time);
    for (; (uint64_t)time(NULL) < stop_time && (MainConfig::target_tgid < 0 || !kill(MainConfig::target_tgid, 0));)
    {
        if (fds.fd >= 0)
        {
            while (true)
            {
                int n = poll(&fds, 1, -1);
                CHECK_ERR_RN1(n < 0, "Poll error");
                CHECK_ERR_RN1(fds.revents & POLLERR, "Got POLLERR, event source is gone");
                if (fds.revents & POLLPRI)
                {
                    fprintf(stderr, _RED "Event triggered!\n" _RE);
                    break;
                }
            }
        }
        for (auto Item : StackCollectorList)
            Item->activate(true);
        sleep(MainConfig::delay);
        for (auto Item : StackCollectorList)
            Item->activate(false);
        for (auto Item : StackCollectorList)
            std::cout << std::string(*Item);
    }
    timeout = true;
    return 0;
};

void end_handle(void)
{
    signal(SIGINT, SIG_IGN);
    for (auto Item : StackCollectorList)
    {
        Item->activate(false);
        if (!timeout)
        {
            std::cout << std::string(*Item) << std::endl;
        }
        Item->finish();
    }
    if (MainConfig::command.length())
    {
        kill(MainConfig::target_tgid, SIGTERM);
    }
};