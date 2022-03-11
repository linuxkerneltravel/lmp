#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <string.h>

#define SAMPLE_PERIOD 0x7fffffffffffffffULL

typedef struct CPU_PACKED         //定义一个cpu occupy的结构体
{
	char name[20];             //定义一个char类型的数组名name有20个元素
	unsigned int user;        //定义一个无符号的int类型的user
	unsigned int nice;        //定义一个无符号的int类型的nice
	unsigned int system;    //定义一个无符号的int类型的system
	unsigned int idle;         //定义一个无符号的int类型的idle
	unsigned int iowait;
	unsigned int irq;
	unsigned int softirq;
}CPU_OCCUPY;

double cal_cpuoccupy (CPU_OCCUPY *o, CPU_OCCUPY *n)
{
    double od, nd;
    double id, sd;
    double cpu_use ;
 
    od = (double) (o->user + o->nice + o->system +o->idle+o->softirq+o->iowait+o->irq);//第一次(用户+优先级+系统+空闲)的时间再赋给od
    nd = (double) (n->user + n->nice + n->system +n->idle+n->softirq+n->iowait+n->irq);//第二次(用户+优先级+系统+空闲)的时间再赋给od
 
    id = (double) (n->idle);    //用户第一次和第二次的时间之差再赋给id
    sd = (double) (o->idle) ;    //系统第一次和第二次的时间之差再赋给sd
    if((nd-od) != 0)
		cpu_use =100.0 - ((id-sd))/(nd-od)*100.00; //((用户+系统)乖100)除(第一次和第二次的时间差)再赋给g_cpu_used
    else
		cpu_use = 0;
    return cpu_use;
}

// 封装系统调用
static int
perf_event_open(struct perf_event_attr *event, pid_t pid,
			int cpu, int group_fd, unsigned long flags)
{
	int ret;
	
	ret = syscall(__NR_perf_event_open, event, pid,
			cpu, group_fd, flags);
	return ret;
}

// 封装错误退出
void err_exit(const char* str)
{
	fprintf(stderr, "Error opening leader %s\n", str);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	FILE *fd;
	char buff[256];
	// nr_cpus为在线CPU数
	int i, j, nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	
	long long cpu_clk;
	long long cpu_cyr;
	
	// PMU文件描述符、本次数据与上次数据
	int fd_cpu_clk[nr_cpus];
	int fd_cpu_cyr[nr_cpus];
	
	long long data_cpu_clk[nr_cpus];
	long long data_cpu_cyr[nr_cpus];
	
	long long prev_cpu_clk[nr_cpus];
	long long prev_cpu_cyr[nr_cpus];
	
	CPU_OCCUPY data_cpustat[nr_cpus];
	CPU_OCCUPY prev_cpustat[nr_cpus];
	
	double cpu_rate;
	
	struct perf_event_attr attr_cpu_clk;
	struct perf_event_attr attr_cpu_cyr;
	
	memset(&attr_cpu_clk, 0, sizeof(struct perf_event_attr));
	memset(&attr_cpu_cyr, 0, sizeof(struct perf_event_attr));

	
	attr_cpu_clk.type			= PERF_TYPE_SOFTWARE;
	attr_cpu_clk.size			= sizeof(struct perf_event_attr);
	attr_cpu_clk.config			= PERF_COUNT_SW_CPU_CLOCK;
	attr_cpu_clk.sample_period	= SAMPLE_PERIOD;
	attr_cpu_clk.disabled		= 1;

	attr_cpu_cyr.type			= PERF_TYPE_HARDWARE;
	attr_cpu_cyr.size			= sizeof(struct perf_event_attr);
	attr_cpu_cyr.config			= PERF_COUNT_HW_CPU_CYCLES;
	attr_cpu_cyr.sample_period	= SAMPLE_PERIOD;
	attr_cpu_cyr.disabled		= 1;

	
	for (i = 0; i < nr_cpus; i++) {
		// cpu cycle
		fd_cpu_clk[i] = perf_event_open(&attr_cpu_clk, -1,
											i, -1, 0);
		
		if (fd_cpu_clk[i] == -1)
			err_exit("PERF_COUNT_HW_CPU_CYCLES");
		
		ioctl(fd_cpu_clk[i], PERF_EVENT_IOC_RESET, 0);
		ioctl(fd_cpu_clk[i], PERF_EVENT_IOC_ENABLE, 0);
		
		// cpu ref cycle
		fd_cpu_cyr[i] = perf_event_open(&attr_cpu_cyr, -1,
											i, -1, 0);
											
		if (fd_cpu_cyr[i] == -1)
			err_exit("PERF_COUNT_SW_CPU_CLOCK");
		
		ioctl(fd_cpu_cyr[i], PERF_EVENT_IOC_RESET, 0);
		ioctl(fd_cpu_cyr[i], PERF_EVENT_IOC_ENABLE, 0);
		
	}
	
	while (1) {
		sleep(1);
		
		for (i = 0; i < nr_cpus; i++) {
			
			fd = fopen("/proc/stat", "r");
			fgets(buff, sizeof(buff), fd);
			
			for(j = 0; j < i + 1; j++)
				fgets(buff, sizeof(buff), fd);
			
			sscanf(buff, "%s %u %u %u %u %u %u %u",
					(char *)&data_cpustat[i].name,
					&data_cpustat[i].user,
					&data_cpustat[i].nice,
					&data_cpustat[i].system,
					&data_cpustat[i].idle,
					&data_cpustat[i].iowait,
					&data_cpustat[i].irq,
					&data_cpustat[i].softirq);
			
			fclose(fd);
			
			cpu_rate = cal_cpuoccupy ((CPU_OCCUPY *)&data_cpustat[i], (CPU_OCCUPY *)&prev_cpustat[i]);

			read(fd_cpu_clk[i], &data_cpu_clk[i], sizeof(data_cpu_clk[i]));
			read(fd_cpu_cyr[i], &data_cpu_cyr[i], sizeof(data_cpu_cyr[i]));
			
			cpu_clk	= data_cpu_clk[i] - prev_cpu_clk[i];
			cpu_cyr	= data_cpu_cyr[i] - prev_cpu_cyr[i];
			
			if (i) {
				continue;
			}
			double new_rate = cpu_cyr * 1000.0 / (22 * cpu_clk);
			if (new_rate > 100.0) {
				new_rate = 100.0;
			}

			printf("CPU:%d CPU_CLOCK:%lld CPU_CYCLES:%lld RATE: %16.5f %16.5f\n",
									i,
									cpu_clk,
									cpu_cyr,
									new_rate,
									cpu_rate);
			
			prev_cpu_clk[i] = data_cpu_clk[i];
			prev_cpu_cyr[i] = data_cpu_cyr[i];
			prev_cpustat[i] = data_cpustat[i];
		}
	}
	
	return 0;
}
