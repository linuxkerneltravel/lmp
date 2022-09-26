from bcc import BPF
import argparse
import time

parser = argparse.ArgumentParser(description='XDP Filter')

parser.add_argument("-t", "--time_limit",type=int,default=20, help="limit the run time(secs)")
parser.add_argument("-i", "--interface",default="lo", help="interface to attatch XDP program")
parser.add_argument("-m", "--mode",type=int,default=0, help="XDP mode(0 for generic,1 for native)")

args = parser.parse_args()

if(args.mode == 0):
    mode = BPF.XDP_FLAGS_SKB_MODE
if(args.mode == 1):
    mode = BPF.XDP_FLAGS_DRV_MODE

b = BPF(src_file = "forward.bpf.c")

b.attach_xdp(dev=args.interface, fn=b.load_func("xdp_fwd", BPF.XDP),flags=mode)
print("attached")

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