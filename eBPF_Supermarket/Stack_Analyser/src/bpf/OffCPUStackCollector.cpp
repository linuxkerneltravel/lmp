#include "bpf/OffCPUStackCollector.h"

OffCPUStackCollector::OffCPUStackCollector()
{
    scale.Period = 1 << 20;
    scale.Type = "OffCPUTime";
    scale.Unit = "milliseconds";
};

double OffCPUStackCollector::count_value(void *data)
{
    return *(uint32_t *)data;
};

int OffCPUStackCollector::load(void)
{
    StackProgLoadOpen(skel->bss->apid = pid;);
    return 0;
}

int OffCPUStackCollector::attach(void)
{
    defaultAttach;
    return 0;
}

void OffCPUStackCollector::detach(void) {
    defaultDetach;
}

void OffCPUStackCollector::unload(void) {
    defaultUnload;
}