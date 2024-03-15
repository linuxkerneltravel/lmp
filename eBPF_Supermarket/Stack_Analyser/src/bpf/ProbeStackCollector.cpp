#include "bpf/ProbeStackCollector.h"

double StackCountStackCollector::count_value(void *data) {
    return *(uint32_t*)data;
}

StackCountStackCollector::StackCountStackCollector()
{
    scale = {
        .Type = "StackCounts",
        .Unit = "Counts",
        .Period = 1,
    };
};

void StackCountStackCollector::setScale(std::string probe)
{
    this->probe = probe;
    scale.Type = (probe + scale.Type).c_str();
};

int StackCountStackCollector::load(void)
{
    StackProgLoadOpen();
    return 0;
};

int StackCountStackCollector::attach(void)
{
    skel->links.handle =
        bpf_program__attach_kprobe(skel->progs.handle, false, probe.c_str());
    CHECK_ERR(!skel->links.handle, "Fail to attach kprobe");
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
