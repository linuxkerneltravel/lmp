/*!
 * \brief ipc_watcher工具环境参数，接收自命令行参数，或配置文件
 * \file  ConfigArgs.h
 * */

#ifndef IPC_IPC_WATCHER_CONFIG_ARGS_H
#define IPC_IPC_WATCHER_CONFIG_ARGS_H

#include <string>

namespace ipc::ipcWatcher {
/*!
 * 1. 命令行参数解析
 *      - -u --uds 追踪unix domain socket
 *      - -m --mmap 追踪mmap
 *      - --filter_path=/path/to/file 追踪指定路径下的文件
 *      - --payload 是否打印 payload， 为保证性能，仅支持过滤状态跟踪，可使用 --force 强制开启全局payload打印
 *      - --force 强制开启全局payload打印
 *      - --pcap_file=/path/to/file.pcap 将输出结果保存为pcap文件，可以使用wireshark进行分析
 *      - --vvv --verbose 输出更多信息
 *      - -v --version 输出版本信息
 *      - -h --help 输出帮助信息
 * */
struct ConfigArgs {
    bool traceUds;
    bool traceMmap;
    bool traceNoAnonUds;  /** 非匿名UDS，例如 /tmp/sample.uds */
    bool printPayload;
    bool forcePayload;
    bool readFromJson;
    bool verbose;
    std::string filterPath;
    std::string pcapFile;

    ConfigArgs()
    : traceUds(false),
      traceMmap(false),
      traceNoAnonUds(false),
      printPayload(false),
      forcePayload(false),
      readFromJson(false),
      verbose(false)
    {
    }

    ~ConfigArgs() = default;
};

}  // namespace ipc::ipcWatcher

#endif //IPC_IPC_WATCHER_CONFIG_ARGS_H
