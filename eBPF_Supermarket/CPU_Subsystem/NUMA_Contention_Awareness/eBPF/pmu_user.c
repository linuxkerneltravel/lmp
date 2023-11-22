#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"


unsigned long pre00 = 0;
unsigned long pre01 = 0;
unsigned long pre10 = 0;
unsigned long pre11 = 0;
unsigned long pre20 = 0;
unsigned long pre21 = 0;


#define NODE_0	0
#define NODE_1 	1

int current_cold = -1;
int current_hot = -1;

int calories_value = 0;

int node0_calories = 0;
int node1_calories = 0;

long LLC_entropy = 0;
long QPI_entropy = 0;
long IMC_entropy = 0;

unsigned long llc_miss_node0 = 0;
unsigned long llc_miss_node1 = 0;
unsigned long qpi_data_node0 = 0;
unsigned long qpi_data_node1 = 0;
unsigned long imc_read_ndoe0 = 0;
unsigned long imc_read_node1 = 0;


int llc_entropy_node0 = 0;
int llc_entropy_node1 = 0;
int qpi_entropy_node0 = 0;
int qpi_entropy_node1 = 0;
int imc_entropy_node0 = 0;
int imc_entropy_node1 = 0;

void reset_zero(void)
{
	LLC_entropy = 0;
	QPI_entropy = 0;
	IMC_entropy = 0;
		
	llc_entropy_node0 = 0;
	llc_entropy_node1 = 0;
	qpi_entropy_node0 = 0;
	qpi_entropy_node1 = 0;
	imc_entropy_node0 = 0;
	imc_entropy_node1 = 0;
		
	calories_value = 0;
		
	node0_calories = 0;
	node1_calories = 0;
}

int main(int argc, char **argv)
{
	char file_name[200];
	
	snprintf(file_name, sizeof(file_name), "%s_kern.o", argv[0]);
	if (load_bpf_file(file_name)) {
		printf("%s", bpf_log_buf);
		
		return 1;
	}
	
	int fd0 = map_fd[0];
	int fd1 = map_fd[1];
	int fd2 = map_fd[2];
	
	__u32 cpu0 = 0;
	__u32 cpu4 = 4;
	


	
	for (;;) {
		/* node0 */
		bpf_map_lookup_elem(fd0, &cpu0, &llc_miss_node0);
		//printf("llc_miss_node0: %lu\n", llc_miss_node0);
		/*
		if (llc_miss_node0 != pre00) {
			curr_llc_miss_node0 = llc_miss_node0;
		}
			//printf("llc_entropy_node0: %lu\n", llc_entropy_node0);
		pre00 = llc_miss_node0;
		*/

		/* node1 */
		bpf_map_lookup_elem(fd0, &cpu4, &llc_miss_node1);
		//printf("llc_miss_node1: %lu\n", llc_miss_node1);
		/*
		if (llc_miss_node1 != pre01)
			printf("llc_miss_node1: %lu\n", llc_miss_node1);
		pre01 = llc_miss_node1;
		*/

		
		if (llc_miss_node0 != pre00 || 
		    		llc_miss_node1 != pre01)
			LLC_entropy = llc_miss_node1 - llc_miss_node0;
		//printf("LLC_entropy:%d\n", LLC_entropy);
		pre00 = llc_miss_node0;
		pre01 = llc_miss_node1;

		if (LLC_entropy != 0) {
			if (LLC_entropy > 0) {
				llc_entropy_node1++;
				llc_entropy_node0--;
			} else {
				llc_entropy_node1--;
				llc_entropy_node0++;
			}

		}
		
		//printf("llc_entropy_node1:%d\n", llc_entropy_node1);
		//printf("llc_entropy_node0:%d\n", llc_entropy_node0);
		

		/* node0 */
		bpf_map_lookup_elem(fd1, &cpu0, &qpi_data_node0);
		//printf("qpi_data_node0: %lu\n", qpi_data_node0);
		/*
		if (qpi_data != pre10)
			printf("Node0 Total QPI data: %lu\n", qpi_data);
		pre10 = qpi_data;
		*/

		/* node1 */
		bpf_map_lookup_elem(fd1, &cpu4, &qpi_data_node1);
		//printf("qpi_data_node1: %lu\n", qpi_data_node1);
		/*
		if (qpi_data != pre11)
			printf("Node1 Total QPI data: %lu\n", qpi_data);
		pre11 = qpi_data;
		*/

		
		if (qpi_data_node0 != pre10 || 
		    		qpi_data_node1 != pre11)
			QPI_entropy = qpi_data_node1 - qpi_data_node0;
		
		//printf("QPI_entropy:%d\n", QPI_entropy);
		pre10 = qpi_data_node0;
		pre11 = qpi_data_node1;

		if (QPI_entropy != 0) {
			if (QPI_entropy > 0) {
				qpi_entropy_node1++;
				qpi_entropy_node0--;
			} else {
				qpi_entropy_node1--;
				qpi_entropy_node0++;
			}
		}
		//printf("qpi_entropy_node1:%d\n", qpi_entropy_node1);
		//printf("qpi_entropy_node0:%d\n", qpi_entropy_node0);
		

		/* node0 */
		bpf_map_lookup_elem(fd2, &cpu0, &imc_read_ndoe0);
		//printf("imc_read_ndoe0: %lu\n", imc_read_ndoe0);
		/*
		if (imc_read != pre20)
			printf("Node0 Total IMC read: %lu\n", imc_read);
		pre20 = imc_read;
		*/

		/* node1 */
		bpf_map_lookup_elem(fd2, &cpu4, &imc_read_node1);
		//printf("imc_read_node1: %lu\n", imc_read_node1);
		/*
		if (imc_read != pre21)
			printf("Node1 Total IMC read: %lu\n", imc_read);
		pre21 = imc_read;
		*/

		if (imc_read_ndoe0 != pre20 || 
		    		imc_read_node1 != pre21)
			IMC_entropy = imc_read_node1 - imc_read_ndoe0;
		
		//printf("IMC_entropy:%d\n", IMC_entropy);
		
		pre20 = imc_read_ndoe0;
		pre21 = imc_read_node1;

		if (IMC_entropy != 0) {
			if (IMC_entropy > 0) {
				imc_entropy_node1++;
				imc_entropy_node0--;
			} else {
				imc_entropy_node1--;
				imc_entropy_node0++;
			}
		}
		//printf("imc_entropy_node1:%d\n", imc_entropy_node1);
		//printf("imc_entropy_node0:%d\n", imc_entropy_node0);
		

		node0_calories = llc_entropy_node0 + qpi_entropy_node0 + imc_entropy_node0;
		node1_calories = llc_entropy_node1 + qpi_entropy_node1 + imc_entropy_node1;

		calories_value = node1_calories - node0_calories;
		
		/*
		printf("node1_calories:%d\n", node1_calories);
		printf("node0_calories:%d\n", node0_calories);
		printf("calories_value:%d\n", calories_value);
		

		
		printf("llc_entropy_node1:%d\n", llc_entropy_node1);
		printf("qpi_entropy_node1:%d\n", qpi_entropy_node1);
		printf("imc_entropy_node1:%d\n", imc_entropy_node1);
		*/
		


		//sleep(2);
		
		if (calories_value != 0) {
			if (calories_value > 0) {
				current_cold = NODE_0;
				current_hot  = NODE_1;

			} else {
				current_cold = NODE_1;
				current_hot  = NODE_0;
			}

			printf("Cold: node%d	Hot: node%d\n", current_cold, current_hot);

		}
		
		reset_zero();

		//sleep(1);
	}
	
	return 0;
}
