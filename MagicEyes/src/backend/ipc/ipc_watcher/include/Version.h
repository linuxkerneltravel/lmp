/*!
 * \brief ipcwatcher 版本信息
 * \file Version.h
 * */

#ifndef IPC_IPC_WATCHER_VERSION_H
#define IPC_IPC_WATCHER_VERSION_H

#include <string>
#if __cplusplus >= 202002L
#include <format>
namespace fmt = std;
#else
#include "fmt/format.h"
#endif

namespace ipc::ipcWatcher {

const std::string kIpcWatcherVersion {"0.0.1"};
int printVersion() {
    fmt::print("ipc_watcher version: {}\n", kIpcWatcherVersion);
    return 0;
}
}  // namespace ipc::ipcWatcher

#endif //IPC_IPC_WATCHER_VERSION_H
