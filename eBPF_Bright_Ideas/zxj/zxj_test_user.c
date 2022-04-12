#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "libbpf.h"
#include "bpf_load.h"

#define	ts	500
#define is	20
#define tr	50
#define ir	3

#define NORMAL	0
#define ATTACK	1	
#define HIGH_ACCESS	2
#define RANDOM	3
#define FIX	4

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned char u8; 

//xdp中固化到sysfs文件系统的map空间路径
static const char *one_file = "/sys/fs/bpf/xdp/globals/map_xdp_one";
static const char *two_file = "/sys/fs/bpf/xdp/globals/map_xdp_two";

int main(int argc, char **argv)
{
	//将数据指标提取模块加载到内核中
	char filename[256];

	snprintf(filename, sizeof(filename), "zxj_data_kern.o");
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	//读取map空间，并进行检测算法的分析
	int recv_fd = map_fd[0];
	int retr_fd = map_fd[1];
	int one_fd, two_fd;

	int ret;
	//	int N;
	u32 lookup_key, next_key;
	u32 Ts, Tr, Is, Ir;
	u16 value;
	u8 val = 1;
	u8 flags;

	one_fd = bpf_obj_get(one_file);
	two_fd = bpf_obj_get(two_file);

Loop:
	sleep(1);	

	//判断系统是否遭受SYN Flood攻击
	lookup_key = 0;
	ret = bpf_map_lookup_elem(recv_fd, &lookup_key, &value);

	if (ret == 0)
	{
		bpf_map_delete_elem(recv_fd, &lookup_key);
		Ts = value;
	}
	else
		Ts = 0;

	ret = bpf_map_lookup_elem(retr_fd, &lookup_key, &value);
	if (ret == 0)
	{
		bpf_map_delete_elem(retr_fd, &lookup_key);
		Tr = value;
	}
	else
		Tr = 0;

	if (Ts < ts)
		flags = NORMAL;
	else if (Tr < tr)
		flags = HIGH_ACCESS;
	else
		flags = ATTACK;

	lookup_key = 0;
	bpf_map_update_elem(one_fd, &lookup_key, &flags, BPF_ANY);

	if (Ts > 0)
	{
		lookup_key = -1;
		//		N = 0;
		while(bpf_map_get_next_key(recv_fd, &lookup_key, &next_key) == 0)
		{
			lookup_key = next_key;
			if (lookup_key == 0)
				continue;
			bpf_map_lookup_elem(recv_fd, &lookup_key, &value);

			//clear map
			bpf_map_delete_elem(recv_fd, &lookup_key);

			Is = value;
			if (Is >= is)
				bpf_map_update_elem(one_fd, &lookup_key, &val, BPF_ANY);
			//		N++;
		}
	}

	if (Tr > 0)
	{
		if (flags == ATTACK)
		{
			lookup_key = -1;
			while(bpf_map_get_next_key(retr_fd, &lookup_key, &next_key) == 0)
			{
				lookup_key = next_key;
				if (lookup_key == 0)
					continue;
				bpf_map_lookup_elem(retr_fd, &lookup_key, &value);

				//clear map
				bpf_map_delete_elem(retr_fd, &lookup_key);

				bpf_map_update_elem(two_fd, &lookup_key, &val, BPF_ANY);
			}
		}
		else
		{
			lookup_key = -1;
			while(bpf_map_get_next_key(retr_fd, &lookup_key, &next_key) == 0)
			{
				lookup_key = next_key;
				if (lookup_key == 0)
					continue;
				bpf_map_lookup_elem(retr_fd, &lookup_key, &value);

				//clear map
				bpf_map_delete_elem(retr_fd, &lookup_key);

				Ir = value;
				if (Ir > ir)
					bpf_map_update_elem(two_fd, &lookup_key, &val, BPF_ANY);
			}

		}
	}

	goto Loop;

	return 0;
}
