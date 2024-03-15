#include "bpf/TemplateClass.h"

// ========== implement virtual func ==========

double TemplateClass::count_value(void *data)
{
    return *(uint32_t*)data;
};

int TemplateClass::load(void)
{
    return 0;
};

int TemplateClass::attach(void)
{
    return 0;
};

void TemplateClass::detach(void){};

void TemplateClass::unload(void){};

// ========== other implementations ========== 

TemplateClass::TemplateClass(){};