#ifndef FRAGINFO_H
#define FRAGINFO_H

#define MAX_ORDER 10
typedef __u64 u64;


struct zone_info {
    u64 zone_ptr;
    u64 zone_start_pfn;
    u64 spanned_pages;
    u64 present_pages;
    char comm[32];
};

struct pgdat_info {
    u64 pgdat_ptr;
    int nr_zones;
    int node_id;
};

#endif
