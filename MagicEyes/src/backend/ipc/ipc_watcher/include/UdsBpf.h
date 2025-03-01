//
// Created by fzy on 2025/2/11.
//

#ifndef IPC_IPC_WATCHER_UDS_BPF_H
#define IPC_IPC_WATCHER_UDS_BPF_H

#include <string>
#include <unordered_map>
#include <memory>
#include <optional>
#include "ConfigArgs.h"
#include "ipcwatcher.h"
extern "C" {
#include "ipc/ipcwatcher/uds.skel.h"
}

namespace ipc::ipcWatcher {

class UdsBpf final {
private:
    enum class FormatType : std::uint8_t {
        kPrintNormal8 = 0,
        kPrintWithPayload9,
        kReserve,
    };
    enum class PrintType : std::uint8_t {
        kTerminal = 0,
        kPcap,
        kOther
    };
private:
    ConfigArgs& config_;
    uds_bpf *skel_;
    //perf_buffer *pb;
    ring_buffer *rb_;
    std::string data_;
    const int kPollPeriodMs {200};
    FormatType type_;
    PrintType printType_;

    std::string formatHeader;
    std::string formatHeaderVars;
    std::unique_ptr<std::unordered_map<std::uint32_t, std::string>> pidCommandHash_;

    std::optional<struct uds_transfer_data> udsData_;   /** 只有需要输出到pcap文件中采用 */

public:
    explicit UdsBpf(ConfigArgs& config);
    ~UdsBpf();
    void open();
    void load();
    void openAndLoad();
    void attach();
    void destroy();
    void setRodataFlags(int value) {
        skel_->rodata->filter_is_exist_path = value;
    }
    void setBpfProgsLoadOpt();
    void poll();
private:
    static void handleEvent(void *ctx, void *data, size_t len);
    static std::string pidToCommand(std::uint32_t pid);
    std::string findCommand(std::uint32_t pid);
    static void handleCommand(std::string& command);
    static std::string getUdsType(int enumId);
    void setAndPrintHeader(FormatType type);
    void saveToPcap();
};

} // namespace ipc::ipcWatcher

#endif //IPC_IPC_WATCHER_UDS_BPF_H
