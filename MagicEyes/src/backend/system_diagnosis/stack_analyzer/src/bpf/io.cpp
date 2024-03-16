
#include "bpf/io.h"

double IOStackCollector::count_value(void *data)
{
    io_tuple *p = (io_tuple *)data;
    switch (DataType)
    {
    case AVE:
        return 1. * p->size / p->count;
    case SIZE:
        return p->size;
    case COUNT:
        return p->count;
    default:
        return 0;
    }
};

void IOStackCollector::setScale(io_mod mod)
{
    DataType = mod;
    static const char *Types[] = {"IOCount", "IOSize", "AverageIOSize"};
    static const char *Units[] = {"counts", "bytes", "bytes"};
    scale.Type = Types[mod];
    scale.Unit = Units[mod];
    scale.Period = 1;
};

IOStackCollector::IOStackCollector()
{
    setScale(DataType);
};

int IOStackCollector::load(void)
{
    StackProgLoadOpen();
    return 0;
}

int IOStackCollector::attach(void)
{
    defaultAttach;
    return 0;
}

void IOStackCollector::detach(void)
{
    defaultDetach;
}

void IOStackCollector::unload(void)
{
    defaultUnload;
}
