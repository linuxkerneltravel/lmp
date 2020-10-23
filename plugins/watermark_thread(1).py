#!/usr/bin/env python
# coding=utf-8

from bcc import BPF
import os
import sys
from time import sleep
import thread

def load_BPF(thread_name, delay):
    b = BPF(text = '''
            #include <uapi/linux/ptrace.h>

            int kprobe_wakeup_kswapd(struct pt_regs *ctx)
            {
                    bpf_trace_printk("Tracing for function of wakeup_kswapd...\\n");
                    bpf_trace_printk("WARNING:A zone is low on free memory!\\n");

                    return 0;
            }
            ''')


    b.trace_print()

def zone_info(thread_name, delay):
	path = "/proc/zoneinfo"

	while 1:
		try:
			sleep(1)
		except keyboardInterrupt:
			exit()
		f = open( path )
		line = f.readline()
		pages_free = '0'
		managed = '0'
		count = 0
		while line:
			if ':' in line:
				line = line.replace(':', '')
			strline = line.split()
			if strline[0] == 'Node':
				print(line)
			if strline[0] == 'pages':
				pages_free = strline[2]
				count = count + 1
		
			if strline[0] == 'managed':
				managed = strline[1]
				count = count + 1
			if pages_free != '0' and managed != '0' and count ==2:
				result = float(pages_free)/float(managed)
				print('%.2f' % result)
				count = 0

			line = f.readline()
		print('------------')
		f.close()
try:
    thread.start_new_thread(load_BPF, ("BPF progream", 0))
    thread.start_new_thread(zone_info, ("zoneinfo", 10))
except:
    print"Error:unable to start thread"

while 1:
    pass
