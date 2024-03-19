#ifndef _SA_IO_H__
#define _SA_IO_H__

#include <asm/types.h>
typedef struct
{
    __u64 size : 40;
    __u64 count : 24;
} io_tuple;

#ifdef __cplusplus
#include "bpf/io_count.skel.h"
#include "bpf/eBPFStackCollector.h"

class IOStackCollector : public StackCollector
{
private:
    declareEBPF(io_count_bpf);

public:
    enum io_mod
    {
        COUNT,
        SIZE,
        AVE,
    } DataType = COUNT;

protected:
    virtual double count_value(void *);

public:
    void setScale(io_mod mod);
    IOStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
};
#endif

#endif