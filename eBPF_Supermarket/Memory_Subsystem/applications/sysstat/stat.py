from bcc import BPF
import time 
import sys
import os
import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--type", default="lru", help="parameter")
    
    return parser.parse_args()

args = parse_args()
b = BPF(src_file="stat.c")
b.attach_kprobe(event_re="get_page_from_freelist", fn_name="sysstat")

def callback(ctx, data, size):
      event = b['buffer'].event(data)
      if args.type == "lru":
            print("%8u %8u %8u %8u %8u %8u %8u" 
                    % (event.anon_active+event.file_active, event.file_active, event.anon_active, event.file_inactive+event.anon_inactive, event.file_inactive, event.anon_inactive, event.unevictable))
      if args.type == "working":
            print("%7u %8u %6u %9u %8u" 
                    % (event.working_nodes, event.working_refault, event.working_activate, event.working_restore, event.working_nodereclaim))
      if args.type == "page":
            print("%8u %11u %10u %11u  --- %4u  --- %6u %9u %13u   --- %4u %11u" 
                    % (event.anon_isolated, event.anon_mapped, event.file_isolated, event.file_mapped,
                        event.shmem, 
                        event.slab_reclaimable+event.slab_unreclaimable, event.slab_reclaimable, event.slab_unreclaimable,
                        event.anon_thps, event.pmdmapped))


b['buffer'].open_ring_buffer(callback)
print("Printing openat() calls, ctrl-c to exit.")

try:
    while 1:
        if args.type == "lru":
            print("%8s %6s %9s %11s %4s %8s %15s" % ("ACTIVE", "FILE","ANON", "INACTIVE", "FILE", "ANON", "UNEVICTABLE"))
        if args.type == "working":
            print("%8s %8s %8s %8s %8s" % ("NODES", "REFAULT", "ACTIVATE", "RESTORE", "NODERECLAIM"))
        if args.type == "page":
            print("ANON:%8s %6s  FILE:%8s %8s %9s %9s %14s %8s %8s %8s" % ("ISOLATED", "MAPPED", "ISOLATED", "MAPPED", "SHMEM", "SLAB", "RECLAIMABLE", "UNRECLAIMABLE", "ANONHUGEPAGE", "SHMEMPMDMAPPED"))
        b.ring_buffer_consume()
        time.sleep(1)
        os.system('clear')

except KeyboardInterrupt:
   sys.exit()
