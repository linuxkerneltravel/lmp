//
// Created by fzy on 2025/2/18.
//
#include "PcapGenerator.h"
#include "spdlog/spdlog.h"

using namespace ipc::ipcWatcher;

//template<class DataStruct>
PcapGenerator::PcapGenerator(std::string& path)
    : path_(path),
      handler_(pcap_open_dead(DLT_RAW, 65535))
{
    dumper_ = pcap_dump_open(handler_, path_.data());
    if (dumper_ == nullptr) {
        SPDLOG_ERROR("pcap_dump_open error");
        pcap_close(handler_);
        handler_ = nullptr;
    }
}

PcapGenerator::~PcapGenerator() {

}

/*!
 * \brief 将数据写入pcap文件
 * \details
 *   1. 构造一个简单的数据包头部
 *   2. 分配内存来存储数据包
 *   3. 写入数据包到 pcap 文件
 * */
void PcapGenerator::WriteToPcap(const UDSData& data) {
    const char* payload;

    if (dumper_ == nullptr) {
        //std::cerr << "Pcap file not opened" << std::endl;
        return;
    }

    struct pcap_pkthdr header;
    header.ts.tv_sec = time(nullptr);
    header.ts.tv_usec = 0;
    header.caplen = sizeof(UDSData) + data.event.size;
    header.len = header.caplen;

    uint8_t* packet = new uint8_t[header.caplen];
    memcpy(packet, &data, sizeof(UDSData));
    memcpy(packet + sizeof(UDSData), payload, data.event.size);

    pcap_dump(reinterpret_cast<u_char*>(dumper_), &header, packet);
    delete[] packet;
}

