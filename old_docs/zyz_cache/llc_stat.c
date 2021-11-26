#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

#define SAMPLE_PERIOD 0x7fffffffffffffffULL

static long
perf_event_open(struct perf_event_attr *event, pid_t pid,
			int cpu, int group_fd, unsigned long flags)
{
	int ret;
	
	ret = syscall(__NR_perf_event_open, event, pid, cpu,
			group_fd, flags);
	return ret;
}

int main(int argc, char **argv)
{
	int i, nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	
	struct perf_event_attr attr_hw_instructions = {
		.freq = 0,
		.sample_period = SAMPLE_PERIOD,
		.inherit = 0,
		.type = PERF_TYPE_HARDWARE,
		.read_format = 0,
		.sample_type = 0,
		.config = PERF_COUNT_HW_INSTRUCTIONS,
	};
	
	
	struct perf_event_attr attr_hw_cache_references = {
		.freq = 0,
		.sample_period = SAMPLE_PERIOD,
		.inherit = 0,
		.type = PERF_TYPE_HARDWARE,
		.read_format = 0,
		.sample_type = 0,
		.config = PERF_COUNT_HW_CACHE_REFERENCES,
	};
	
	struct perf_event_attr attr_hw_cache_misses = {
		.freq = 0,
		.sample_period = SAMPLE_PERIOD,
		.inherit = 0,
		.type = PERF_TYPE_HARDWARE,
		.read_format = 0,
		.sample_type = 0,
		.config = PERF_COUNT_HW_CACHE_MISSES,
	};
	
	int fd_instructions[nr_cpus];
	int fd_cache_references[nr_cpus];
	int fd_cache_misses[nr_cpus];
	

	long long data_instructions[nr_cpus];
	long long data_cache_references[nr_cpus];
	long long data_cache_misses[nr_cpus];
	

	long long last_instructions[nr_cpus];
	long long last_cache_references[nr_cpus];
	long long last_cache_misses[nr_cpus];
	

	for(i = 0; i < nr_cpus; i++) {
		fd_instructions[i] = perf_event_open(&attr_hw_instructions, -1, i, -1, 0);
		if (fd_instructions[i] == -1) {
			fprintf(stderr, "Error opening leader %s\n", "PERF_COUNT_HW_INSTRUCTIONS");
			exit(EXIT_FAILURE);
		}
		ioctl(fd_instructions[i], PERF_EVENT_IOC_RESET, 0);
		ioctl(fd_instructions[i], PERF_EVENT_IOC_ENABLE, 0);
		
		
		fd_cache_references[i] = perf_event_open(&attr_hw_cache_references, -1, i, -1, 0);
		if (fd_cache_references[i] == -1) {
			fprintf(stderr, "Error opening leader %s\n", "PERF_COUNT_HW__CACHE_REFERENCES");
			exit(EXIT_FAILURE);
		}
		ioctl(fd_cache_references[i], PERF_EVENT_IOC_RESET, 0);
		ioctl(fd_cache_references[i], PERF_EVENT_IOC_ENABLE, 0);
		
		fd_cache_misses[i] = perf_event_open(&attr_hw_cache_misses, -1, i, -1, 0);
		if (fd_cache_misses[i] == -1) {
			fprintf(stderr, "Error opening leader %s\n", "PERF_COUNT_HW_CACHE_MISSES");
			exit(EXIT_FAILURE);
		}
		ioctl(fd_cache_misses[i], PERF_EVENT_IOC_RESET, 0);
		ioctl(fd_cache_misses[i], PERF_EVENT_IOC_ENABLE, 0);
		
	}
	
	while (1) {
		sleep(1);
		
		for (i = 0; i < nr_cpus; i++) {
			read(fd_instructions[i], &data_instructions[i], sizeof(data_instructions[i]));
			read(fd_cache_references[i], &data_cache_references[i], sizeof(data_cache_references[i]));
			read(fd_cache_misses[i], &data_cache_misses[i], sizeof(data_cache_misses[i]));
			
			printf("CPU%2d:%16lld\t%16lld\t%16lld\n", i, 
					data_instructions[i] - last_instructions[i],
					data_cache_references[i] - last_cache_references[i],
					data_cache_misses[i] - last_cache_misses[i]);
			
			last_instructions[i] = data_instructions[i];
			last_cache_references[i] = data_cache_references[i];
			last_cache_misses[i] = data_cache_misses[i];
			
		}

		printf("=====\n");
	}
	
	return 0;
}
