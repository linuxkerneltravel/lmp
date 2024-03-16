#include "bpf/eBPFStackCollector.h"
#include "probe.skel.h"

class StackCountStackCollector : public StackCollector
{
private:
    struct probe_bpf *skel = __null;

public:
    std::string probe;

protected:
    virtual double count_value(void *);

public:
    void setScale(std::string probe);
    StackCountStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
};
