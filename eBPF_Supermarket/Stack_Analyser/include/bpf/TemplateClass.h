#ifndef _TEMPLATE_H__
#define _TEMPLATE_H__

// ========== C code part ==========

// ========== C code end ========== 

#ifdef __cplusplus
// ========== C++ code part ==========
#include "bpf/template.skel.h"
#include "bpf/eBPFStackCollector.h"

class TemplateClass : public StackCollector
{
private:
    declareEBPF(template_bpf);

protected:
    virtual double count_value(void *);

public:
    TemplateClass();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
};
// ========== C++ code end ==========
#endif

#endif