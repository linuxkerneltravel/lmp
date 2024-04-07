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

#include "sa_user.h"
#include "clipp.h"

uint64_t stop_time = -1;
bool timeout = false;
uint64_t IntTmp;
std::string StrTmp;
clipp::man_page *man_page;

namespace MainConfig
{
    uint64_t run_time = -1; // 运行时间
    unsigned delay = 5;     // 设置输出间隔
    std::string command = "";
    int32_t target_pid = -1;
    std::string trigger = "";    // 触发器
    std::string trig_event = ""; // 触发事件
}

std::vector<StackCollector *> StackCollectorList;

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
        Item->detach();
        Item->unload();
    }
    if (MainConfig::command.length())
    {
        kill(MainConfig::target_pid, SIGTERM);
    }
}

int main(int argc, char *argv[])
{
    man_page = new clipp::man_page();
    clipp::group cli;
    {
        auto TraceOption = (clipp::option("-u")
                                    .call([]
                                          { StackCollectorList.back()->ustack = true; }) %
                                "Sample user stacks",
                            clipp::option("-k")
                                    .call([]
                                          { StackCollectorList.back()->kstack = true; }) %
                                "Sample kernel stacks\n");

        auto OnCpuOption = (clipp::option("on_cpu")
                                .call([]
                                      { StackCollectorList.push_back(new OnCPUStackCollector()); }) %
                            COLLECTOR_INFO("on-cpu")) &
                           ((clipp::option("-f") &
                             clipp::value("freq", IntTmp)
                                 .call([]
                                       { static_cast<OnCPUStackCollector *>(StackCollectorList.back())
                                             ->setScale(IntTmp); })) %
                                "Set sampling frequency",
                            TraceOption);

        auto OffCpuOption = clipp::option("off_cpu")
                                    .call([]
                                          { StackCollectorList.push_back(new OffCPUStackCollector()); }) %
                                COLLECTOR_INFO("off-cpu") &
                            (TraceOption);

        auto MemleakOption = (clipp::option("memleak")
                                  .call([]
                                        { StackCollectorList.push_back(new MemleakStackCollector()); }) %
                              COLLECTOR_INFO("memleak")) &
                             ((clipp::option("-i") &
                               clipp::value("interval", IntTmp)
                                   .call([]
                                         { static_cast<MemleakStackCollector *>(StackCollectorList.back())
                                               ->sample_rate = IntTmp; })) %
                                  "Set the sampling interval",
                              clipp::option("-w")
                                      .call([]
                                            { static_cast<MemleakStackCollector *>(StackCollectorList.back())
                                                  ->wa_missing_free = true; }) %
                                  "Free when missing in kernel to alleviate misjudgments",
                              TraceOption);

        auto IOOption = clipp::option("io")
                                .call([]
                                      { StackCollectorList.push_back(new IOStackCollector()); }) %
                            COLLECTOR_INFO("io") &
                        (TraceOption);

        auto ReadaheadOption = clipp::option("readahead")
                                       .call([]
                                             { StackCollectorList.push_back(new ReadaheadStackCollector()); }) %
                                   COLLECTOR_INFO("readahead") &
                               (TraceOption);

        auto ProbeOption = clipp::option("probe")
                                   .call([]
                                         { StackCollectorList.push_back(new ProbeStackCollector()); }) %
                               COLLECTOR_INFO("probe") &
                           (clipp::value("probe", StrTmp)
                                    .call([]
                                          { static_cast<ProbeStackCollector *>(StackCollectorList.back())
                                                ->setScale(StrTmp); }) %
                                "Set the probe string" &
                            TraceOption);

        auto LlcStatOption = clipp::option("llc_stat").call([]
                                                            { StackCollectorList.push_back(new LlcStatStackCollector()); }) %
                                 COLLECTOR_INFO("llc_stat") &
                             ((clipp::option("-i") &
                               clipp::value("period", IntTmp)
                                   .call([]
                                         { static_cast<LlcStatStackCollector *>(StackCollectorList.back())
                                               ->setScale(IntTmp); })) %
                                  "Set sampling period",
                              TraceOption);

        auto MainOption = _GREEN "Some overall options" _RE %
                          ((
                               ((clipp::option("-p") &
                                 clipp::value("pid", MainConfig::target_pid)) %
                                "Set the pid of the process to be tracked; default is -1, which keeps track of all processes") |
                               ((clipp::option("-c") &
                                 clipp::value("command", MainConfig::command)) %
                                "Set the command to be run and sampled; defaults is none")),
                           (clipp::option("-d") &
                            clipp::value("interval", MainConfig::delay)) %
                               "Set the output delay time (seconds); default is 5",
                           (clipp::option("-t") &
                            clipp::value("duration", MainConfig::run_time)
                                .call([]
                                      { stop_time = time(NULL) + MainConfig::run_time; })) %
                               "Set the total sampling time; default is __INT_MAX__",
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
                          .call([]
                                { std::cout << *man_page << std::endl; exit(0); }) %
                      "Show man page"));

        cli = (OnCpuOption,
               OffCpuOption,
               MemleakOption,
               IOOption,
               ReadaheadOption,
               ProbeOption,
               LlcStatOption,
               MainOption,
               Info);
    }
    {
        auto fmt = clipp::doc_formatting{}
                       .first_column(3)
                       .doc_column(25)
                       .last_column(128);
        *man_page = clipp::make_man_page(cli, argv[0], fmt)
                        .prepend_section("DESCRIPTION", _RED "Count the function call stack associated with some metric.\n" _RE BANNER)
                        .append_section("LICENSE", _RED "Apache Licence 2.0" _RE);
    }
    if (!clipp::parse(argc, argv, cli))
    {
        std::cerr << *man_page << std::endl;
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
    CHECK_ERR(child_exec_event_fd < 0, "failed to create event fd");
    if (MainConfig::command.length())
    {
        MainConfig::target_pid = fork();
        switch (MainConfig::target_pid)
        {
        case -1:
        {
            CHECK_ERR(true, "Command create failed.");
        }
        case 0:
        {
            const auto bytes = read(child_exec_event_fd, &eventbuff, sizeof(eventbuff));
            CHECK_ERR(bytes < 0, "Failed to read from fd %ld", bytes)
            else CHECK_ERR(bytes != sizeof(eventbuff), "Read unexpected size %ld", bytes);
            printf("child exec %s\n", MainConfig::command.c_str());
            CHECK_ERR_EXIT(execl("/bin/bash", "bash", "-c", MainConfig::command.c_str(), NULL), "failed to execute child command");
            break;
        }
        default:
        {
            printf("Create child %d\n", MainConfig::target_pid);
            break;
        }
        }
    }

    for (auto Item = StackCollectorList.begin(); Item != StackCollectorList.end();)
    {
        fprintf(stderr, _RED "Attach collecotor%d %s.\n" _RE,
                (int)(Item - StackCollectorList.begin()) + 1, (*Item)->getName());
        (*Item)->pid = MainConfig::target_pid;
        if ((*Item)->load() || (*Item)->attach())
            goto err;
        Item++;
        continue;
    err:
        fprintf(stderr, _ERED "Collector %s err.\n" _RE, (*Item)->scales->Type.c_str());
        (*Item)->detach();
        (*Item)->unload();
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
        CHECK_ERR(fds.fd < 0, "%s open error", path);
        fds.events = POLLPRI;
        CHECK_ERR(write(fds.fd, trig, strlen(trig) + 1) < 0, "%s write error", path);
        fprintf(stderr, _RED "Waiting for events...\n" _RE);
    }
    fprintf(stderr, _RED "Running for %lus or Hit Ctrl-C to end.\n" _RE, MainConfig::run_time);
    for (; (uint64_t)time(NULL) < stop_time && (MainConfig::target_pid < 0 || !kill(MainConfig::target_pid, 0));)
    {
        if (fds.fd >= 0)
        {
            while (true)
            {
                int n = poll(&fds, 1, -1);
                CHECK_ERR(n < 0, "Poll error");
                CHECK_ERR(fds.revents & POLLERR, "Got POLLERR, event source is gone");
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
}