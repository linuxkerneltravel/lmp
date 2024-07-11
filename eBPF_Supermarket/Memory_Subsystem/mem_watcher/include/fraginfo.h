#ifndef FRAGINFO_H
#define FRAGINFO_H

#define MAX_ORDER 10
typedef __u64 u64;
struct order_zone{
    unsigned int order;
    u64 zone_ptr;
};
struct ctg_info {
	long unsigned int free_pages;
	long unsigned int free_blocks_total;
	long unsigned int free_blocks_suitable;
};

struct zone_info
{
    u64 zone_ptr;
    u64 zone_start_pfn;
    u64 spanned_pages;
    u64 present_pages;
    char comm[32];
    unsigned int order;
};

struct pgdat_info
{
    u64 pgdat_ptr;
    int nr_zones;
    int node_id;
};

#endif
