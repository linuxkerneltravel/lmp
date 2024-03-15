#include "bpf/ProbeStackCollector.h"
#include "uprobe_helpers.h"
#include <iostream>

double StackCountStackCollector::count_value(void *data)
{
    return *(uint32_t *)data;
}

StackCountStackCollector::StackCountStackCollector()
{
    scale = {
        .Type = "StackCounts",
        .Unit = "Counts",
        .Period = 1,
    };
};
void splitString(std::string symbol, const char split, std::vector<std::string> &res)
{
    if (symbol == "")
        return;
    std::string strs = symbol + split;
    size_t pos = strs.find(split);
    while (pos != strs.npos)
    {
        std::string temp = strs.substr(0, pos);
        res.push_back(temp);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(split);
    }
}
void StackCountStackCollector::setScale(std::string probe)
{
    this->probe = probe;
    auto type = new std::string(probe+scale.Type);
    scale.Type = type->c_str();
};

int StackCountStackCollector::load(void)
{
    StackProgLoadOpen(skel->bss->apid = pid;);
    return 0;
};

int StackCountStackCollector::attach(void)
{
    std::vector<std::string> strList;
    splitString(probe, ':', strList);

    if (strList.size() == 1 || (strList.size() == 3 && strList[0] == "p" && strList[1] == ""))
    {
        // probe a kernel function
        std::string func = probe;
        if (strList.size() == 3 && strList[0] == "p" && strList[1] == "")
            func = strList[2];
        skel->links.handle =
            bpf_program__attach_kprobe(skel->progs.handle, false, func.c_str());
        CHECK_ERR(!skel->links.handle, "Fail to attach kprobe111");
        return 0;
    }
    else if (strList.size() == 3 && strList[0] == "t")
    {
        // probe a kernel tracepoint
        skel->links.handle_tp =
            bpf_program__attach_tracepoint(skel->progs.handle_tp, strList[1].c_str(), strList[2].c_str());
        CHECK_ERR(!skel->links.handle_tp, "Fail to attach tracepoint");
        return 0;
    }
    else if (strList.size() == 2 || (strList.size() == 3 && strList[0] == "p" && strList[1] != ""))
    {
        // probe a user-space function in the library 'lib'
        
        return 0;
    }
    else if (strList.size() == 3 && strList[0] == "u")
    {
        // probe a USDT tracepoint
        return 0;
    }
    else
    {
        printf("Type must be 'p', 't', or 'u' or too any args");
    }

    scale.Type = (probe + scale.Type).c_str();

    return 0;
};

void StackCountStackCollector::detach(void)
{
    defaultDetach;
};

void StackCountStackCollector::unload(void)
{
    defaultUnload;
};
