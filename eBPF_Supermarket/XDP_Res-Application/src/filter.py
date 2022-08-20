from bcc import BPF
import time
import ctypes as ct
import rules

b = BPF(src_file = "filter.bpf.c")

def rules_merge():
    rules_list = rules.rule_pretreat(rules.rules_raw)
    rules_merged = {"ipproto":{},"saddr":{},"daddr":{},"sport":{},"dport":{},"action":{}}
    keys = list(rules_merged.keys())
    i = 1
    for r in rules_list:
        for k in range(0,5):
            #print(keys[k],r[k])
            if r[k] not in rules_merged[keys[k]]:
                rules_merged[keys[k]][r[k]] = i
            else:
                rules_merged[keys[k]][r[k]] |= i
        rules_merged['action'][i] = r[5]
        i = i<< 1
    for k in range(0,5):
        if 65535 in rules_merged[keys[k]]:
            for j,v in rules_merged[keys[k]].items():
                if j != 65535:
                    rules_merged[keys[k]][j] &= rules_merged[keys[k]][65535]
    print(rules_merged)
    return rules_merged

def rules_to_map():
    '''
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
    '''
    rules_merged = rules_merge()
    i = 0
    for k,v in rules_merged['ipproto'].items():
        ipproto_map_keys[i] = ct.c_uint(k)
        ipproto_map_values[i] = ct.c_uint(v)
        i += 1
    i = 0
    for k,v in rules_merged['saddr'].items():
        saddr_map_keys[i] = ct.c_uint(k)
        saddr_map_values[i] = ct.c_uint(v)
        i += 1
    i = 0
    for k,v in rules_merged['daddr'].items():
        daddr_map_keys[i] = ct.c_uint(k)
        daddr_map_values[i] = ct.c_uint(v)
        i += 1
    i = 0
    for k,v in rules_merged['sport'].items():
        sport_map_keys[i] = ct.c_ushort(k)
        sport_map_values[i] = ct.c_uint(v)
        i += 1
    i = 0
    for k,v in rules_merged['dport'].items():
        dport_map_keys[i] = ct.c_ushort(k)
        dport_map_values[i] = ct.c_uint(v)
        i += 1
    i = 0
    for k,v in rules_merged['action'].items():
        action_map_keys[i] = ct.c_uint(k)
        action_map_values[i] = ct.c_uint(v)      
        i += 1  


    b['ipproto_map'].items_update_batch(ipproto_map_keys,ipproto_map_values)
    b['saddr_map'].items_update_batch(saddr_map_keys,saddr_map_values)
    b['daddr_map'].items_update_batch(daddr_map_keys,daddr_map_values)
    b['sport_map'].items_update_batch(sport_map_keys,sport_map_values)
    b['dport_map'].items_update_batch(dport_map_keys,dport_map_values)
    b['action_map'].items_update_batch(action_map_keys,action_map_values)

    

        
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

b.attach_xdp(dev="eth0", fn=b.load_func("xdp_filter", BPF.XDP),flags=BPF.XDP_FLAGS_SKB_MODE)
print("xdp attached")
print(b['ipproto_map'].items())
print(b['dport_map'].items())

time_count = 0
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
    time_count += 1
    if(time_count == 30):
        break


b.remove_xdp("eth0", BPF.XDP_FLAGS_SKB_MODE)
