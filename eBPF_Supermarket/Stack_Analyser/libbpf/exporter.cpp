#include <arpa/inet.h>
#include <iostream>
#include <map>
// #include <iomanip>
#include "include/sa_user.h"
#include "include/clipp.h"
#include "string.h"

namespace MainConfig {
    std::string server_address = "127.0.0.1:12345";
    int target_pid = -1;
};

struct myComp {
    bool operator()(psid a, psid b) const {
        return a.pid < b.pid;
    }
};

int main(int argc, char *argv[]) {
    auto cli = (
        (clipp::option("-s", "--server") & clipp::value("server address, default 127.0.0.1:12345", MainConfig::server_address)) % "set the server address"
    );

    if (!clipp::parse(argc, argv, cli)) {
		std::cout << clipp::make_man_page(cli, argv[0]) << '\n';
		return 0;
	}
		// 创建 socket
	int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == -1) {
		std::cerr << "Error creating socket" << std::endl;
		return -1;
	}
    // 服务器地址信息
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    auto ColonPos = MainConfig::server_address.find(':');
    if(ColonPos < 0) {
        std::cerr << "server address err" << std::endl;
        return -1;
    }
    auto IPAddr = MainConfig::server_address.substr(0, ColonPos);
    auto PortAddr = MainConfig::server_address.substr(ColonPos + 1);
    serverAddress.sin_port = htons(std::stoi(PortAddr));
    inet_pton(AF_INET, IPAddr.c_str(), &serverAddress.sin_addr);
    // 连接到服务器
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Error connecting to server" << std::endl;
        close(clientSocket);
        return -1;
    }
    char buf[4096];
#define b_scanf(cmp, content, ...) if(scanf(content, ##__VA_ARGS__) cmp 0) break;
    for(;;) {
        b_scanf(<=, " time:%s", buf);
        std::string filename(buf);
        std::map<psid, uint32_t, myComp> counts;
        b_scanf(<, " counts:");
        b_scanf(<=, " pid\tusid\tksid\t%s", buf);
        filename += buf;
        for(;;) {
            psid k;
            uint64_t v;
            b_scanf(<=, " %u\t%d\t%d\t%lu", &k.pid, &k.usid, &k.ksid, &v);
            counts[k] = v;
        }
        printf("get counts\n");
        std::map<int32_t, std::vector<std::string>> traces;
        b_scanf(<, " traces:");
        b_scanf(<, " sid\ttrace");
        for(;;) {
            int32_t k;
            std::vector<std::string> v;
            b_scanf(<=, " %d\t", &k);
            b_scanf(<=, "%s", buf);
            char *p = strtok(buf, ";");
            while(p) {
                v.push_back(std::string(p));
                p = strtok(NULL, ";");
            }
            traces[k] = v;
        }
        printf("get traces\n");
        std::map<int32_t, int32_t> groups;
        b_scanf(<, " groups:");
        b_scanf(<, " pid\ttgid");
        for(;;) {
            int32_t k, v;
            b_scanf(<=, " %d\t%d", &k, &v);
            groups[k] = v;
        }
        printf("get groups\n");
        std::map<int32_t, std::string> comms;
        b_scanf(<, " commands:");
        b_scanf(<, " pid\tcommand");
        for(;;) {
            int32_t k;
            char comm[16];
            b_scanf(<=, " %d\t%s", &k, comm);
            comms[k] = std::string(comm);
        }
        printf("get commands\n");
        b_scanf(<, " OK");
        fflush(stdin);
        std::ostringstream oss;
        for(auto count : counts) {
            oss << groups[count.first.pid] << ';';
            oss << count.first.pid << ':' << comms[count.first.pid] << ';';
            for(auto sym : traces[count.first.usid]) {
                oss << sym << ';';
            }
            for(auto sym : traces[count.first.ksid]) {
                oss << sym << ';';
            }
            oss << count.second << '\n';
        }
        printf("format\n");
        std::string data = oss.str();
        // 发送数据到服务器
        // std::cout << data;
        auto len = data.size();
        if(!len) {
            printf("no data\n");
            continue;
        }
        struct diy_header AHeader = {
            .len = len
        };
        strcpy(AHeader.name, filename.c_str());
        AHeader.magic = 0;
        send(clientSocket, &AHeader, sizeof(AHeader), 0);
        printf("send header {.len = %lu}\n", AHeader.len);
        send(clientSocket, data.c_str(), AHeader.len, 0);
        printf("send data\n");
    }
// 关闭连接
	close(clientSocket);
    return 0;
}