#ifndef _MY_PMU_MYPMU_H
#define _MY_PMU_MYPMU_H

/* 
 * LLC cache miss function
 */
extern void enable_l3_cache_miss(void);
extern void enable_PC0_in_global_counter(void);
extern unsigned long total_l3_cache_misses(void);

extern void disable_l3_cache_miss(void);

/*
 * QPI performance event
 */
extern void enable_data_from_qpi(void);
extern void enable_PC2_in_global_counter(void);
extern unsigned long total_data_from_qpi(void);

extern void disable_data_from_qpi(void);

/*
 * IMC performance event
 */
extern void enable_qmc_normal_reads_any(void);
extern void enable_PC3_in_global_counter(void);
extern unsigned long total_qmc_normal_reads_any(void);

extern void disable_qmc_normal_reads_any(void);

/*
 * Disable all MSR_UNCORE_PMCx in global counter
 */
extern void disable_global_counter(void);

#endif		/* _MY_PMU_MYPMU_H */
