from bcc import BPF
import time
import ctypes as ct
import rules
import argparse

parser = argparse.ArgumentParser(description='XDP Filter')

parser.add_argument("-t", "--time_limit",type=int,default=20, help="limit the run time(secs)")
parser.add_argument("-i", "--interface",default="lo", help="interface to attatch XDP program")
parser.add_argument("-m", "--mode",type=int,default=0, help="XDP mode(0 for generic,1 for native)")

args = parser.parse_args()

if(args.mode == 0):
    mode = BPF.XDP_FLAGS_SKB_MODE
if(args.mode == 1):
    mode = BPF.XDP_FLAGS_DRV_MODE

b = BPF(src_file = "filter_rewrite_test.bpf.c")

def rules_to_map():
    rules_list = rules.rule_pretreat(rules.rules_raw)
    i = 1
    for r in rules_list:
        if(r[0] != 0):
            ipproto_map_values[i] = ct.c_uint(i)
            ipproto_map_keys[i] = ct.c_uint(r[0])
        if(r[1] != 0):
            saddr_map_values[i] = ct.c_uint(i)
            saddr_map_keys[i] = ct.c_uint(r[1])
        if(r[2] != 0):
            daddr_map_values[i] = ct.c_uint(i)
            daddr_map_keys[i] = ct.c_uint(r[2])
        if(r[3] != 0):
            sport_map_values[i] = ct.c_uint(i)
            sport_map_keys[i] = ct.c_ushort(r[3])
        if(r[4] != 0):
            dport_map_values[i] = ct.c_uint(i)
            dport_map_keys[i] = ct.c_ushort(r[4])

        action_map_keys[i] = ct.c_uint(i)
        action_map_values[i] = ct.c_uint(r[5])

        b['ipproto_map'].items_update_batch(ipproto_map_keys,ipproto_map_values)
        b['saddr_map'].items_update_batch(saddr_map_keys,saddr_map_values)
        b['daddr_map'].items_update_batch(daddr_map_keys,daddr_map_values)
        b['sport_map'].items_update_batch(sport_map_keys,sport_map_values)
        b['dport_map'].items_update_batch(dport_map_keys,dport_map_values)
        b['action_map'].items_update_batch(action_map_keys,action_map_values)

        i = i<<1
    

        
#map k-v init
ipproto_map_keys = (b['ipproto_map'].Key * 1024)()
ipproto_map_values = (b['ipproto_map'].Leaf * 1024)()
saddr_map_keys = (b['saddr_map'].Key * 1024)()
saddr_map_values = (b['saddr_map'].Leaf * 1024)()
daddr_map_keys = (b['daddr_map'].Key * 1024)()
daddr_map_values = (b['daddr_map'].Leaf * 1024)()
sport_map_keys = (b['sport_map'].Key * 1024)()
sport_map_values = (b['sport_map'].Leaf * 1024)()
dport_map_keys = (b['dport_map'].Key * 1024)()
dport_map_values = (b['dport_map'].Leaf * 1024)()
action_map_keys = (b['action_map'].Key * 1024)()
action_map_values = (b['action_map'].Leaf * 1024)()


rules_to_map()

b.attach_xdp(dev=args.interface, fn=b.load_func("xdp_filter", BPF.XDP),flags=mode)
print("xdp program attached to interface %s in %d mode and will run %d secs"%(args.interface,args.mode,args.time_limit))

time_count = 0
while 1:
    try:
        time.sleep(1)
        time_count += 1
        if(time_count > args.time_limit):
            break
    except KeyboardInterrupt:
        print("Removing filter from device")
        break


b.remove_xdp(args.interface, mode)
