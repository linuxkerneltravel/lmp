#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/smp.h>

/* 
 * LLC total misses
 *
 * Enable funcitons
 */
void enable_l3_cache_miss(void)
{
	/* MSR_UNCORE_PERFEVTSEL0 start address */
	int reg_addr = 0x3C0;	
	
	/* UNC_L3_MISS.READ event number */
	int event_num = 0x09;
	
	/* UNC_L3_MISS.READ umask */
	int umask = 0x01 << 8;
	
	/* 
	 * Reset the counter when writing a new value
	 * Enalble EN(bit 22) and OCC_CTR_RST(bit 17) 
	 */
	int enable_bits = 0x420000;
	int event = enable_bits | umask | event_num;

	__asm__ ("wrmsr" : : "c"(reg_addr), "a"(event), "d"(0x00));
}
EXPORT_SYMBOL_GPL(enable_l3_cache_miss);

void enable_PC0_in_global_counter(void)
{
	/* MSR_UNCORE_PERF_GLOBAL_CTRL start address */
	int reg_addr = 0x391;
	
	/* Enable MSR_UNCORE_PMC0 */
	unsigned long enable_bits = 0x1;

	__asm__("wrmsr" : : "c"(reg_addr), "a"(enable_bits), "d"(0x00));
}
EXPORT_SYMBOL_GPL(enable_PC0_in_global_counter);

unsigned long total_l3_cache_misses(void)
{ 
	unsigned long total_misses;
	unsigned long eax_low, edx_high;
	
	/* MSR_UNCORE_PMC0 start address */
	int reg_addr = 0x3b0;

	__asm__("rdmsr" : "=a"(eax_low), "=d"(edx_high) : "c"(reg_addr));

	total_misses = ((long int)eax_low | (long int)edx_high<<32);

	return total_misses;
}
EXPORT_SYMBOL_GPL(total_l3_cache_misses);

/* 
 * LLC total misses
 *
 * Disable funcitons
 */
void disable_l3_cache_miss(void)
{
	/* MSR_UNCORE_PERFEVTSEL0 start address */ 
	int reg_addr_PEREVTSEL = 0x3C0; 
	
	/* MSR_UNCORE_PMC0 start address */
	int reg_addr_PMCx = 0x3B0;
	
	/* Clears  MSR_UNCORE_PERFEVTSEL0 */
	__asm__("wrmsr" : : "c"(reg_addr_PEREVTSEL), "a"(0x00), "d"(0x00));
	
	/* Clears counter0 */
	__asm__("wrmsr" : : "c"(reg_addr_PMCx), "a"(0x00), "d"(0x00));
}
EXPORT_SYMBOL_GPL(disable_l3_cache_miss);

/*
 * QPI performance event
 *
 * Enable functions
 */
void enable_data_from_qpi(void)
{
	/* MSR_UNCORE_PERFEVTSEL2 start address */
	int reg_addr = 0x3C2;	
	
	/* UNC_GQ_DATA.FROM_QPI event number */
	int event_num = 0x04;
	
	/* UNC_GQ_DATA.FROM_QPI umask */
	int umask = 0x01 << 8;
	
	/* 
	 * Reset the counter when writing a new value
	 * Enalble EN(bit 22) and OCC_CTR_RST(bit 17) 
	 */
	int enable_bits = 0x420000;
	int event = enable_bits | umask | event_num;

	__asm__ ("wrmsr" : : "c"(reg_addr), "a"(event), "d"(0x00));
}
EXPORT_SYMBOL_GPL(enable_data_from_qpi);

void enable_PC2_in_global_counter(void)
{
	/* MSR_UNCORE_PERF_GLOBAL_CTRL start address */
	int reg_addr = 0x391;
	
	/* Enable MSR_UNCORE_PMC2 */
	unsigned long enable_bits = 0x4;

	__asm__("wrmsr" : : "c"(reg_addr), "a"(enable_bits), "d"(0x00));
}
EXPORT_SYMBOL_GPL(enable_PC2_in_global_counter);

unsigned long total_data_from_qpi(void)
{ 
	unsigned long total_data = -1;
	unsigned long eax_low, edx_high;
	
	/* MSR_UNCORE_PMC2 start address */
	int reg_addr = 0x3B2;

	__asm__("rdmsr" : "=a"(eax_low), "=d"(edx_high) : "c"(reg_addr));

	total_data = ((long int)eax_low | (long int)edx_high<<32);

	return total_data;
}
EXPORT_SYMBOL_GPL(total_data_from_qpi);

/*
 * QPI performance event
 *
 * Disable functions
 */
void disable_data_from_qpi(void)
{
	/* MSR_UNCORE_PERFEVTSEL2 start address */ 
	int reg_addr_PEREVTSEL = 0x3C2; 
	int reg_addr_PMCx = 0x3B2;
	
	/* Clears  MSR_UNCORE_PERFEVTSEL2 */
	__asm__("wrmsr" : : "c"(reg_addr_PEREVTSEL), "a"(0x00), "d"(0x00));

	/* Clears counter2 */
	__asm__("wrmsr" : : "c"(reg_addr_PMCx), "a"(0x00), "d"(0x00));
}
EXPORT_SYMBOL_GPL(disable_data_from_qpi);

/*
 * IMC performance event
 *
 * Enable functions
 */
void enable_qmc_normal_reads_any(void)
{
	/* MSR_UNCORE_PERFEVTSEL3 start address */
	int reg_addr = 0x3C3;	
	
	/* UNC_QMC_NORMAL_READS.ANY event number */
	int event_num = 0x2c;
	
	/* UNC_QMC_NORMAL_READS.ANY umask */
	int umask = 0x07 << 8;
	
	/* 
	 * Reset the counter when writing a new value
	 * Enalble EN(bit 22) and OCC_CTR_RST(bit 17) 
	 */
	int enable_bits = 0x420000;
	int event = enable_bits | umask | event_num;

	__asm__ ("wrmsr" : : "c"(reg_addr), "a"(event), "d"(0x00));
}
EXPORT_SYMBOL_GPL(enable_qmc_normal_reads_any);

void enable_PC3_in_global_counter(void)
{
	/* MSR_UNCORE_PERF_GLOBAL_CTRL start address */
	int reg_addr = 0x391;
	
	/* Enable MSR_UNCORE_PMC3 */
	unsigned long enable_bits = 0x8;

	__asm__("wrmsr" : : "c"(reg_addr), "a"(enable_bits), "d"(0x00));
}
EXPORT_SYMBOL_GPL(enable_PC3_in_global_counter);

unsigned long total_qmc_normal_reads_any(void)
{ 
	unsigned long total_normal_reads = -1;
	unsigned long eax_low, edx_high;
	
	/* MSR_UNCORE_PMC3 start address */
	int reg_addr = 0x3B3;

	__asm__("rdmsr" : "=a"(eax_low), "=d"(edx_high) : "c"(reg_addr));

	total_normal_reads = ((long int)eax_low | (long int)edx_high<<32);

	return total_normal_reads;
}
EXPORT_SYMBOL_GPL(total_qmc_normal_reads_any);

/*
 * IMC performance event
 *
 * Disable functions
 */
void disable_qmc_normal_reads_any(void)
{
	/* MSR_UNCORE_PERFEVTSEL3 start address */ 
	int reg_addr_PEREVTSEL = 0x3C3; 
	int reg_addr_PMCx = 0x3B3;
	
	/* Clears  MSR_UNCORE_PERFEVTSEL3 */
	__asm__("wrmsr" : : "c"(reg_addr_PEREVTSEL), "a"(0x00), "d"(0x00));

	/* Clears counter3 */
	__asm__("wrmsr" : : "c"(reg_addr_PMCx), "a"(0x00), "d"(0x00));
}
EXPORT_SYMBOL_GPL(disable_qmc_normal_reads_any);

/*
 * Disable all MSR_UNCORE_PMCx in global counter
 */
void disable_global_counter(void)
{
	/* MSR_UNCORE_PERF_GLOBAL_CTRL start address */
	int reg_addr = 0x391;
	
	/* Clears MSR_UNCORE_PERF_GLOBAL_CTRL */
	__asm__("wrmsr" : : "c"(reg_addr), "a"(0x00), "d"(0x00));
}
EXPORT_SYMBOL_GPL(disable_global_counter);
