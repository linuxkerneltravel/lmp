from __future__ import print_function

import os
import sys

sys.path.append(os.path.realpath("../visual"))

import argparse
from ctypes import *
from time import asctime, localtime, sleep, time

from bcc import BPF



############## pre defines #################
ROOT_PATH = "/sys/class/net"
IFNAMSIZ = 16
COL_WIDTH = 10
MAX_QUEUE_NUM = 1024

# structure for network interface name array
class Devname(Structure):
    _fields_ = [('name', c_char * IFNAMSIZ)]


############## arguments #################
parser = argparse.ArgumentParser(description="")
parser.add_argument("-n", "--name", type=str, default="")
parser.add_argument("-i", "--interval", type=float, default=1)
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
parser.add_argument("--print", action="store_true", help="print results to terminal")
parser.add_argument("--visual", action="store_true", help="enable visualization with influxdb-grafana")
args = parser.parse_args()

if args.name == "":
    print("Please specify a network interface.")
    exit()
else:
    dev_name = args.name

if len(dev_name) > IFNAMSIZ - 1:
    print("NIC name too long")
    exit()

print_interval = args.interval + 0.0
if print_interval <= 0:
    print("print interval must stricly positive")
    exit()

if args.visual:
    from utils import export_nic_throughput

################## printer for results ###################
def to_str(num):
    s = ""
    if num > 1000000:
        return str(round(num / (1024 * 1024.0), 2)) + 'M'
    elif num > 1000:
        return str(round(num / 1024.0, 2)) + 'K'
    else:
        if isinstance(num, float):
            return str(round(num, 2))
        else:
            return str(num)


def print_table(table, qnum, dir):
    global print_interval

    if args.print or args.visual:

        if args.print:
            # -------- print headers --------
            if dir=="TX":
                print(asctime(localtime(time())))
            print(dir)
            print("%-11s %-11s %-11s %-11s" % ("QueueID", "avg_size", "BPS", "PPS"))

        # -------- calculates --------
        qids = []
        tBPS = tPPS = tAVG = tpkt = tlen = 0
        for k, v in table.items():
            qids += [k.value]
            tlen += v.total_pkt_len
            tpkt += v.num_pkt
        tBPS = tlen / print_interval
        tPPS = tpkt / print_interval
        if tpkt != 0:
            tAVG = tlen / tpkt

        # -------- print table --------
        for k in range(qnum):
            if k in qids:
                item = table[c_ushort(k)]
                data = [k, item.total_pkt_len, item.num_pkt]
            else:
                data = [k, 0, 0]

            # -------- print a line per queue --------
            avg = 0
            if data[2] != 0:
                avg = data[1] / data[2]
            BPS = data[1] / print_interval
            PPS = data[2] / print_interval
            if args.print:
                print("%-11d %-11s %-11s %-11s" % (data[0], to_str(avg), to_str(BPS), to_str(PPS)))
            if args.visual:
                export_nic_throughput(dev_name, data[0], avg, BPS, PPS, "nic_throughput_" + dir)

        # -------- print total --------
        if args.print:
            print("%-11s %-11s %-11s %-11s" % ("Total", to_str(tAVG), to_str(tBPS), to_str(tPPS)))
            if dir=="RX":
                print("-" * 60)
        if args.visual:
            export_nic_throughput(dev_name, 'total', tAVG, tBPS, tPPS, "nic_throughput_" + dir)


################ get number of queues #####################
tx_num = 0
rx_num = 0
path = ROOT_PATH + "/" + dev_name + "/queues"
if not os.path.exists(path):
    print("Net interface", dev_name, "does not exits.")
    exit()

list = os.listdir(path)
for s in list:
    if s[0] == 'r':
        rx_num += 1
    if s[0] == 't':
        tx_num += 1

if tx_num > MAX_QUEUE_NUM or rx_num > MAX_QUEUE_NUM:
    print("number of queues over 1024 is not supported.")
    exit()

################## start tracing ##################
b = BPF(src_file="nic_throughput.c")
devname_map = b['name_map']
_name = Devname()
_name.name = dev_name.encode()
devname_map[0] = _name

count = 0

while 1:

    count += 1
    if count > args.count:
        break

    try:
        sleep(print_interval)
    except KeyboardInterrupt:
        exit()

    # -------- print tx queues --------
    print_table(b['tx_q'], tx_num, "TX")
    b['tx_q'].clear()

    # -------- print rx queues --------
    print_table(b['rx_q'], rx_num, "RX")
    b['rx_q'].clear()
    
