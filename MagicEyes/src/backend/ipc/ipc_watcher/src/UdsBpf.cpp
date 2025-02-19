//
// Created by fzy on 2025/2/12.
//
#include <filesystem>
#include <fstream>

#include "UdsBpf.h"
#include "ipcwatcher.h"
#include "spdlog/spdlog.h"
#include "fmt/format.h"
using namespace ipc::ipcWatcher;
namespace fs = std::filesystem;

UdsBpf::UdsBpf(ConfigArgs& config)
    : config_(config),
      skel_(nullptr),
      //pb(nullptr),
      rb_(nullptr),
      formatHeader(),
      pidCommandHash_(std::make_unique<std::unordered_map<std::uint32_t, std::string>>()),
      type_(FormatType::kPrintNormal8),
      printType_(PrintType::kTerminal)
{
}

UdsBpf::~UdsBpf() {
    destroy();
}

/*!
 * \brief 打开BPF程序
 * */
void UdsBpf::open() {
    skel_ = uds_bpf::open();
    if (!skel_) {
        SPDLOG_ERROR("Failed to open and load BPF skeleton");
    }

}

/*!
 * \brief 加载BPF程序
 * */
 void UdsBpf::load() {
    int err = uds_bpf::load(skel_);
    if (err) {
        SPDLOG_ERROR("Failed to load BPF program, err：{}", err);
        destroy();
    }
}

/*!
 * \brief 加载并验证BPF程序
 * */
void UdsBpf::openAndLoad() {
    skel_ = uds_bpf::open_and_load();
    if (!skel_) {
        SPDLOG_ERROR("Failed to load and verify BPF skeleton");
        //return 1;
    }
}

/*!
 * \brief 附加kprobe等事件
 * */
void UdsBpf::attach() {
    int err = uds_bpf::attach(skel_);
    if (err) {
        SPDLOG_ERROR("Failed to attach BPF program, err：{}", err);
        destroy();
    }
}

/*!
 * \brief 选择部分事件，独立挂载
 * \details 是否挂载，依据传递的ConfigArgs
 * */
void UdsBpf::setBpfProgsLoadOpt() {
    bpf_program__set_autoload(skel_->progs.unix_dgram_sendmsg, true);
    bpf_program__set_autoload(skel_->progs.unix_dgram_recvmsg, true);
    bpf_program__set_autoload(skel_->progs.unix_stream_sendmsg, true);
    bpf_program__set_autoload(skel_->progs.unix_stream_recvmsg, true);
}

/*!
 * \brief 根据选项要求，设置并打印头部信息
 */
void UdsBpf::setAndPrintHeader(FormatType type) {
    type_ = type;
    switch (type) {
        case FormatType::kPrintNormal8: {
            formatHeader = "{:<14} {:<10} {:<30} {:<10} {:<30} {:<10} {:<12} {:<30}\n";
            fmt::print(formatHeader, "Timestamp", "sendPID", "sendComm",
                       "recvPID", "recvComm", "Size", "Type", "Path");
            break;
        }
        case FormatType::kPrintWithPayload9: {
            formatHeader = "{:<10} {:<10} {:<35} {:<10} {:<35} {:<10} {:<12} {:<30} {:<60}\n";
            fmt::print(formatHeader, "Timestamp", "sendPID", "sendComm",
                       "recvPID", "recvComm", "Size", "Type", "Path", "Payload");
            break;
        }
        case FormatType::kReserve: { /** reserve */
            formatHeader = "{:<10} {:<10} {:<25} {:<10} {:<25}\n";
            fmt::print(formatHeader, "Timestamp", "sendPID", "sendComm",
                       "recvPID", "recvComm");
            break;
        }
        default:
            break;
    }
}

/*!
 * \brief 接收BPF采集的数据，并调用处理函数进行处理
 * */
void UdsBpf::poll() {
    // 设置 ringbuffer 回调
//    rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.uds_events),
//                          reinterpret_cast<ring_buffer_sample_fn>(UdsBpf::handleEvent),
//                          nullptr, nullptr);
    rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.uds_events),
                           reinterpret_cast<ring_buffer_sample_fn>(UdsBpf::handleEvent),
                           this, nullptr);
    if (!rb_) {
        SPDLOG_ERROR("Failed to create uds ring buffer");
        destroy();
    }

    int err;
//    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8,
//                          reinterpret_cast<perf_buffer_sample_fn>(UdsBpf::handleEvent),
//                          nullptr, nullptr, nullptr);
//    if (!pb) {
//        SPDLOG_ERROR("Failed to create perf buffer");
//        err = -1;
//        destroy();
//
//    }
    fmt::print("Tracing UDS send/recv events... Ctrl+C to exit\n");
    setAndPrintHeader(type_);
// 4. 轮询事件
    while (true) {
        //err = perf_buffer__poll(pb, 100 /* timeout_ms */);
        err = ring_buffer__poll(rb_, kPollPeriodMs);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            SPDLOG_ERROR("Error polling ring buffer: {}", err);
            break;
        }
    }
}

/*!
 * \brief 清理释放资源
 * */
void UdsBpf::destroy() {
    ring_buffer__free(rb_);
    //perf_buffer__free(pb);
    uds_bpf::destroy(skel_);
}

/** static */ void UdsBpf::handleEvent(void *ctx, void *data, size_t len) {
    auto udsBpf = reinterpret_cast<UdsBpf*>(ctx);
    auto *e = reinterpret_cast<uds_event*>(data);
    if (udsBpf->type_ == FormatType::kPrintNormal8) {
        fmt::print(udsBpf->formatHeader,   e->timestamp,
                                           e->send_pid,
                                           udsBpf->findCommand(e->send_pid),
                                           e->recv_pid,
                                           udsBpf->findCommand(e->recv_pid),
                                           e->size,
                                           ipc::ipcWatcher::UdsBpf::getUdsType(e->type),
                                           e->path);
    }
    else if (udsBpf->type_ == FormatType::kPrintWithPayload9) {
        fmt::print("reserve");
    }
    else if (udsBpf->type_ == FormatType::kReserve) {
        fmt::print("reserve");
    }
}

/*!
 * \brief 根据pid查找进程名
 * \details 为了加速，避免频繁读取，若哈希表中有，则直接从哈希表中获取，若没有，则从文件系统中获取，并存入哈希表
 * */
std::string UdsBpf::findCommand(std::uint32_t pid) {
    auto it = pidCommandHash_->find(pid);
    if (it != pidCommandHash_->end()) {
        return it->second;
    }
    else {
        std::string cmd = pidToCommand(pid);
        handleCommand(cmd);
        pidCommandHash_->emplace(pid, cmd);
        return cmd;
    }
    /*
     * 使用 try_emplace:
            try_emplace 会在插入时直接构造元素，并返回一个 std::pair，指示插入是否成功以及元素的位置。
            如果元素已经存在，inserted 为 false，it 指向已存在的元素。
            如果元素不存在，inserted 为 true，it 指向新插入的元素
      但不合适，还是会每次调用pidToCommand， 不符合加速要求
    auto [it, inserted] = pidCommandHash_->try_emplace(pid, pidToCommand(pid));
    if (inserted) {
        SPDLOG_DEBUG("Inserted new command for PID {}: {}", pid, it->second);
    }
    return it->second;
    */
}

/*!
 * \brief 处理command，删除命令后带的一系列参数，便于在终端展示
 * \details 可以进一步考虑限制输出大小，例如 {：<25} 强制截取前面的命令
 * */
void UdsBpf::handleCommand(std::string &command) {
    /** 找到第一个空格的位置 */
    size_t spacePos = command.find(' ');
    /** 如果找到了空格，则截取空格之前的部分 */
    if (spacePos != std::string::npos) {
        command = command.substr(0, spacePos);
    }
    /** 如果截取后的字符串长度大于30个字符，则截取前30个字符 */
    if (command.length() > 30) {
        command = command.substr(0, 30);
    }
}

/*!
 * \brief 根据PID获取进程名
 * */
std::string UdsBpf::pidToCommand(std::uint32_t pid) {
    std::string cmdFormatPath {"/proc/{}/cmdline"};
    std::string cmdlinePath = fmt::vformat(cmdFormatPath, fmt::make_format_args(pid));
    fs::path path(cmdlinePath);
    if (!fs::exists(path)) {
        return "";
    }
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    std::string command;
    std::getline(file, command, '\0');
    return command;
}

/*!
 * \brief:   根据type获取UDS类型
 * \details
 *       enum sock_type {
                SOCK_STREAM = 1,
                SOCK_DGRAM = 2,
                SOCK_RAW = 3,
                SOCK_RDM = 4,
                SOCK_SEQPACKET = 5,
                SOCK_DCCP = 6,
                SOCK_PACKET = 10,
         };
 */
std::string UdsBpf::getUdsType(int enumId) {
std::string type {};
switch (enumId) {
    case 1:
        type = "SOCK_STREAM";
        break;
    case 2:
        type = "SOCK_DGRAM";
        break;
    case 3:
        type = "SOCK_RAW";
        break;
    case 4:
        type = "SOCK_RDM";
        break;
    case 5:
        type = "SOCK_SEQPACKET";
        break;
    case 6:
        type = "SOCK_DCCP";
        break;
    case 10:
        type = "SOCK_PACKET";
        break;
    default:
        type = "UNKNOWN";
        break;
    }
    return type;
}

/*!
 * \brief 将数据保存在pcap文件中
 * */
void UdsBpf::saveToPcap() {

}