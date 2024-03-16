#ifndef _SA_ON_CPU_H__
#define _SA_ON_CPU_H__

#include "eBPFStackCollector.h"
#include "on_cpu.skel.h"


#ifdef __cplusplus
class OnCPUStackCollector : public StackCollector
{
private:
	struct on_cpu_bpf *skel = __null;

	int *pefds = NULL;
	int num_cpus = 0;
	struct bpf_link **links = NULL;
	unsigned long long freq = 49;

protected:
	virtual double count_value(void *);

public:
	void setScale(uint64_t freq);
	OnCPUStackCollector();
    virtual int load(void);
    virtual int attach(void);
    virtual void detach(void);
    virtual void unload(void);
};
#endif

#endif