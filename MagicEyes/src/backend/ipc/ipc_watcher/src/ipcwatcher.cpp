/*!
\brief Linux kernel IPC 观测工具, 使用 Linux eBPF 技术
\TODO
    1. 将抓取到的数据，在终端输出
    2. 将抓取到的数据，存入pcap文件中，并可以使用wireshark进行分析
*/
#include <iostream>
#include <csignal>

#include "argparse/argparse.hpp"

#include "spdlog/spdlog.h"  /** 注意 spdlog与fmt的顺序 */
#if __cplusplus >= 202002L
#include <format>
namespace fmt = std;
#else
#include "fmt/format.h"
#endif

#include "UdsBpf.h"
#include "Version.h"
#include "ConfigArgs.h"

std::atomic<bool> g_interrupted(false);

void signalHandler(int signum) {
    if (signum == SIGINT) {
        SPDLOG_INFO("Received SIGINT, preparing to exit...");
        g_interrupted = true;
    }
}

void initSignalHandling() noexcept {
    bool success{true};
    sigset_t signals;
    success = success && (0 == sigfillset(&signals));
    success = success && (0 == sigdelset(&signals, SIGABRT));
    success = success && (0 == sigdelset(&signals, SIGBUS));
    success = success && (0 == sigdelset(&signals, SIGFPE));
    success = success && (0 == sigdelset(&signals, SIGILL));
    success = success && (0 == sigdelset(&signals, SIGSEGV));
    success = success && (0 == pthread_sigmask(SIG_SETMASK, &signals, nullptr));
    if (!success) {
        SPDLOG_ERROR("Failed to initialize signal handling");
    }
    // 注册 SIGINT 信号处理函数
    signal(SIGINT, signalHandler);
}


int cmdParser(argparse::ArgumentParser& parser, ipc::ipcWatcher::ConfigArgs& config) {
    parser.add_argument("-u", "--uds")
        .help("Trace unix domain socket")
        .default_value(false)
        .implicit_value(true)
        .store_into(config.traceUds);
    parser.add_argument("-m", "--mmap")
        .help("Trace mmap")
        .default_value(false)
        .implicit_value(true)
        .store_into(config.traceMmap);
    parser.add_argument("--filterPath")
        .help("Filter path")
        .default_value("")
        .action([&config](const std::string& path) {
            /** --filter_path=/tmp/uds.socket
             * path: /tmp/uds.socket */
            config.filterPath = path;
        });
    parser.add_argument("--traceNoAnonUds")
        .help("only trace no anon uds like /tmp/sample.uds")
        .default_value(false)
        .implicit_value(true)
        .store_into(config.traceNoAnonUds);
    parser.add_argument("--payload")
        .help("Print payload")
        .default_value(false)
        .implicit_value(true)
        .store_into(config.printPayload);
    parser.add_argument("--force")
        .help("Force enable payload printing")
        .default_value(false)
        .implicit_value(true)
        .store_into(config.forcePayload);
    parser.add_argument("--pcapFile")
        .help("Save output to pcap file")
        .default_value("")
        .store_into(config.pcapFile);
    parser.add_argument("--fromJson")
        .help("read config args from json file")
        .default_value(false)
        .implicit_value(true)
        .store_into(config.readFromJson);
    parser.add_argument("--vvv", "--verbose")
        .help("Output more information")
        .default_value(false)
        .implicit_value(true)
        .store_into(config.verbose);
    parser.add_argument("-v", "--version")
        .help("Output version information")
        .default_value(false)
        .implicit_value(true)
        .action(
                [](const std::string& value) {
                    ipc::ipcWatcher::printVersion();
                    exit(0);
                }
                );
//    parser.add_argument("reserve_sample_int")
//        .help("Positional Arguments sample like: <...>/ipcwatcher 10")
//        .scan<'i', int>();
    //config.reserve = parser.get<int>("reserve_int");
    return 0;
}

int main(int argc, char *argv[]) {
    spdlog::set_level(spdlog::level::info);
    //initSignalHandling();
    ipc::ipcWatcher::ConfigArgs config;
    argparse::ArgumentParser parser("ipc_watcher");
    cmdParser(parser, config);
    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        SPDLOG_ERROR("{}", err.what());
        return 1;
    }
    if (config.traceUds) {
        ipc::ipcWatcher::UdsBpf udsBpf(config);
        udsBpf.open();
        udsBpf.load();
        udsBpf.attach();
        while (!g_interrupted) {
            udsBpf.poll();
        }
    }
    else if (config.traceMmap) {
        fmt::print("do not support right now, exiting...\n");
     }
    else {
        fmt::print("No trace type selected, exiting...\n");
    }


}
