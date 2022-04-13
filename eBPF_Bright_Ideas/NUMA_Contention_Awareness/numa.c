#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h> 
#include <my-pmu/mypmu.h>

/*
 * L3 cache miss
 */
void enable_llc_miss(void)
{
	/* Config MSR_UNCORE_PERFEVTSEL */
	enable_l3_cache_miss();

	/* Enable MSR_UNCORE_PERF_GLOBAL_CTRL */
	enable_PC0_in_global_counter();

	total_l3_cache_misses();
}

void disable_l3(void)
{
	/* Disable llc read miss */
	disable_l3_cache_miss();
}	

/*
 * QPI performance event
 */
void enable_qpi(void)
{
	enable_data_from_qpi();
	enable_PC2_in_global_counter();
	
	total_data_from_qpi();
}

void disable_qpi(void)
{
	disable_data_from_qpi();
}

/*
 * IMC performance event
 */
void enable_imc(void)
{
	enable_qmc_normal_reads_any();
	enable_PC3_in_global_counter();

	total_qmc_normal_reads_any();
}

void disable_imc(void)
{
	disable_qmc_normal_reads_any();
}

void enable_msr(void *info)
{
	enable_llc_miss();
	enable_qpi();
	enable_imc();
}

void get_msr(void *info)
{
	total_l3_cache_misses();
	total_data_from_qpi();
	total_qmc_normal_reads_any();
}

void disable_msr(void *info)
{
	disable_l3();
	disable_qpi();
	disable_imc();

	disable_global_counter();
}

void enable_data_node0(void)
{
	smp_call_function_single(0, enable_msr, NULL, 1);
}

void enable_data_node1(void)
{
	smp_call_function_single(4, enable_msr, NULL, 1);
}

/*
void get_data_node0(void)
{
	smp_call_function_single(0, get_msr, NULL, 1);
}

void get_data_node1(void)
{
	smp_call_function_single(4, get_msr, NULL, 1);
}
*/

void disable_data_node0(void)
{
	smp_call_function_single(0, disable_msr, NULL, 1);
}

void disable_data_node1(void)
{
	smp_call_function_single(4, disable_msr, NULL, 1);
}

int __init pmc_init(void)
{
	enable_data_node1();
	enable_data_node0();

	//get_data_node0();
	//get_data_node1();
	
	return 0;
}

void __exit pmc_exit(void)
{
	disable_data_node0();
	disable_data_node1();
}

module_init(pmc_init);
module_exit(pmc_exit);
MODULE_LICENSE("GPL");



