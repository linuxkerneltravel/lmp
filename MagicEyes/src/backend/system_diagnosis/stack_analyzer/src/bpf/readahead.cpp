#include "bpf/readahead.h"

double ReadaheadStackCollector::count_value(void *data)
{
    ra_tuple *p = (ra_tuple *)data;
    return p->expect - p->truth;
};

ReadaheadStackCollector::ReadaheadStackCollector()
{
    showDelta = false;
    scale = {
        .Type = "UnusedReadaheadPages",
        .Unit = "pages",
        .Period = 1,
    };
};

int ReadaheadStackCollector::load(void)
{
    StackProgLoadOpen();
    return 0;
}

int ReadaheadStackCollector::attach(void)
{
    defaultAttach;
    return 0;
}

void ReadaheadStackCollector::detach(void)
{
    defaultDetach;
}

void ReadaheadStackCollector::unload(void)
{
    defaultUnload;
}