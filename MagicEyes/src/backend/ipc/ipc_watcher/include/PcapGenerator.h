/*!
 * \brief pcap文件生成器，基于libpcap
 * */


#ifndef IPC_IPC_WATCHER_PCAP_GENERATOR_H
#define IPC_IPC_WATCHER_PCAP_GENERATOR_H

#include <pcap/pcap.h>
#include <string>

#include "ipcwatcher.h"

namespace ipc::ipcWatcher {

//template<class DataStruct>
class PcapGenerator {
public:
    using UDSData = uds_transfer_data;
    explicit PcapGenerator(std::string& path);
    ~PcapGenerator();

    void WriteToPcap(const UDSData& data);

private:
    std::string path_;
    pcap_t* handler_;
    pcap_dumper* dumper_;
};

}   // namespace ipc::ipcWatcher

#endif //IPC_IPC_WATCHER_PCAP_GENERATOR_H
