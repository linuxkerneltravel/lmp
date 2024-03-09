#include "bpf/eBPFStackCollector.h"
#include "bpf/stack_count.skel.h"

class StackCountStackCollector : public StackCollector
{
private:
    struct stack_count_bpf *skel = __null;

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
