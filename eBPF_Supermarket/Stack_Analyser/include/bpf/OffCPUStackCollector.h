#ifndef _SA_OFF_CPU_H__
#define _SA_OFF_CPU_H__

#include "bpf/eBPFStackCollector.h"
#include "bpf/off_cpu_count.skel.h"

class OffCPUStackCollector : public StackCollector
{
private:
    struct off_cpu_count_bpf *skel = __null;

protected:
    virtual double count_value(void*);

public:
    OffCPUStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
};

#endif