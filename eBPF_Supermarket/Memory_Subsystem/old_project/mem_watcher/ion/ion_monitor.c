#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
//#include <bpf/bpf_load.h>
#include "ion_monitor.h"
#include "ion_monitor.skel.h"
#include <linux/bpf.h>



#define INTERVAL_MAX 6U
int main(int argc, char **argv)
{
	/*
	char file_name[200];

	snprintf(file_name, sizeof(file_name), "%s_kern.o", argv[0]);
	if (load_bpf_file(file_name)) {
		printf("%s", bpf_log_buf);

		return 1;
	}*/
	struct ion_monitor_bpf *skel = ion_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	int fd = bpf_map__fd(skel->maps.time_map);
	int key;
	
	for(;;) {
		sleep(10);
		
		for (key = 0; key < INTERVAL_MAX; key++) {
			unsigned long long value = 0;
			bpf_map_lookup_elem(fd, &key, &value);
			if (key < INTERVAL_MAX - 1)
				printf("Range %dms - %dms\tCount:%llu\n", 
					key * 10, (key + 1) * 10, value);
			else 
				printf("Over  50ms\t\tCount:%llu\n", value);
		}
		
		printf("==========================================\n");
	}
	
	return 0;
}




