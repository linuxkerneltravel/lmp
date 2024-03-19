#ifndef _SA_READAHEAD_H__
#define _SA_READAHEAD_H__

#include <asm/types.h>
typedef struct
{
    __u32 expect;
    __u32 truth;
} ra_tuple;

#ifdef __cplusplus
#include "bpf/pre_count.skel.h"
#include "bpf/eBPFStackCollector.h"

class ReadaheadStackCollector : public StackCollector
{
private:
    declareEBPF(pre_count_bpf);

protected:
    virtual double count_value(void *data);

public:
    ReadaheadStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
};
#endif

#endif