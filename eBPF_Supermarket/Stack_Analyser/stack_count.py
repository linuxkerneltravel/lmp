#!/bin/python
from bcc import BPF, PerfType, PerfSWConfig
import sys
from time import sleep
from copy import copy
from os import system
from psutil import Process
from pyod.models.knn import KNN
from json import dumps, JSONEncoder
from ctypes import c_int32, c_uint32
# from pyod.models.deep_svdd import DeepSVDD
clf_name = 'KNN'
clf = KNN()

# stack data ebpf code
with open('stack_count.bpf.c', encoding='utf-8') as f:
    stack_code = f.read()

# parsing stack level
kern = True
if 'u' in sys.argv:
    kern = False
orin = stack_code.replace('WHICH_STACK', 'BPF_F_USER_STACK' if not kern else '0')

# bpf parsing
b = BPF(text=orin)
print("eBPF initializing compelete.")

# pid parsing
pids = [-1]
if 'pid' in sys.argv:
    pid_str = sys.argv[sys.argv.index('pid')+1].split()
    if '0' not in pid_str and '-' not in pid_str:
        pids = []
        for i in pid_str:
            pid = int(i)
            pids.append(pid)
            try:
                b.add_module(Process(pid).exe())
            except:
                print("no exe for %d" % pid)

# add external sym
for pid in pids:
    b.attach_perf_event(ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_stack",
        sample_period=0, sample_freq=99, pid=pid)

def log(tmp):
        count = [[n.value] for _, n in tmp.items()]
        if len(count) > clf.n_neighbors:
            clf.fit(count)
            labels = clf.labels_
            for (spid,n),label in zip(tmp.items(), labels):
                print('pid:%d\tsid:%d\tcount:%d\tlabel:%d' % (spid.pid, spid.sid, n.value, label))

# get bpf map
# psid_count = b["psid_count"]
# tgid_comm = b["tgid_comm"]
# pid_tgid = b["pid_tgid"]
# stack_trace = b["stack_trace"]

class MyEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, int):
            return obj.value
        else:
            return super(MyEncoder, self).default(obj)

def format_put(file=None, rate_comm:str=None, anomaly_detect=False):
    psid_count = copy(b["psid_count"])
    tgid_comm = copy(b["tgid_comm"])
    pid_tgid = copy(b["pid_tgid"])
    stack_trace = copy(b["stack_trace"])
    tgids = {
        tgid.value:{
            'name':comm.str.decode(),
            'pids':dict()
        } for tgid, comm in tgid_comm.items()
    }

    pt_dict = {pid.value:tgid.value for pid, tgid in pid_tgid.items()}

    count = [[n.value] for _, n in psid_count.items()]
    labels = None
    if anomaly_detect:
        try:
            clf.fit(count)
            labels = clf.labels_.astype(int).tolist()
        except:
            pass
    if labels == None:
        labels = [None for i in range(len(count))]

    for (psid, n), label in zip(psid_count.items(), labels, strict=True):
        tgids[pt_dict[psid.pid]]['pids'][psid.pid] = {
            psid.sid:{
                'trace': [
                    "%#08x:%s" % (j, (
                            b.sym(j, pt_dict[psid.pid], demangle=False) if not kern
                            else b.ksym(j)
                    ).decode('utf-8', 'replace'))
                    for j in stack_trace.walk(psid.sid)
                ],
                'count': n.value,
                'label': label
            }
        }

    print(dumps(tgids, cls=MyEncoder,indent=2,ensure_ascii=True,sort_keys=False,separators=(',', ':')),file=file)
    
    if anomaly_detect and rate_comm != None:
        tp = fp = p = 0
        for tgd in tgids.values():
            if tgd['name'] == rate_comm:
                p += 1
            for pd in tgd['pids'].values():
                f = False
                for sd in pd.values():
                    if sd['label'] == 1:
                        if tgd['name'] == rate_comm:
                            tp += 1
                        else:
                            fp += 1
                        f = True
                        break
                if f:
                    break
        print("recall:%f%% precision:%f%%" % (tp/p*100 if p else 0, tp/(tp+fp)*100 if tp+fp else 0))

# system("tput -x smcup; clear")
while 1:
    try:
        sleep(5)
        # system("clear")
        # psid_count.clear() # slice
        # log(copy(psid_count))
        format_put(rate_comm='make', anomaly_detect=True)

    except KeyboardInterrupt:
        print("\b\bquit...")
        b.detach_perf_event(ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.CPU_CLOCK)
        # system("tput rmcup")
        with open("stack_count.log", "w") as file:
            format_put(file=file, rate_comm='make', anomaly_detect=True)
        exit()