#!/bin/python
from bcc import BPF, PerfType, PerfSWConfig
import sys
from time import sleep
from psutil import Process
from pyod.models.knn import KNN
from json import dumps, JSONEncoder
from signal import signal
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
orin = orin.replace('SIDFALSE', 'sid < 0')

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

def log():
        psid_count = {psid_t(psid):n.value for psid,n in b["psid_count"].items()}
        count = [[n] for n in psid_count.values()]
        if len(count) > clf.n_neighbors:
            clf.fit(count)
            labels = clf.labels_
            for (spid,n),label in zip(psid_count.items(), labels):
                print('pid:%d\tsid:%d\tcount:%d\tlabel:%d' % (spid.pid, spid.sid, n, label))

class MyEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, int):
            return obj.value
        else:
            return super(MyEncoder, self).default(obj)

stack_trace = b["stack_trace"]

class psid_t:
    def __init__(self, psid) -> None:
        self.pid = psid.pid
        self.sid = psid.sid

def format_put(file=None, rate_comm:str=None, anomaly_detect=False):
    psid_count = {psid_t(psid):count.value for psid,count in b["psid_count"].items()}
    tgid_comm = {tgid.value:comm.str.decode() for tgid,comm in b["tgid_comm"].items()}
    pid_tgid = {pid.value:tgid.value for pid,tgid in b["pid_tgid"].items()}

    tgids = {
        tgid:{
            'name':comm,
            'pids':dict()
        } for tgid, comm in tgid_comm.items()
    }
    count = [[n] for n in psid_count.values()]
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
        tgids[pid_tgid[psid.pid]]['pids'][psid.pid] = {
            psid.sid:{
                'trace': [
                    "%#08x:%s" % (j, (
                            b.sym(j, psid.pid) if not kern
                            else b.ksym(j)
                    ).decode('utf-8', 'replace'))
                    for j in stack_trace.walk(psid.sid)
                ],
                'count': n,
                'label': label
            }
        }

    print(dumps(tgids, cls=MyEncoder,indent=2,ensure_ascii=True,sort_keys=False,separators=(',', ':')),file=file)
    
    if anomaly_detect and rate_comm != None:
        tp = fp = p = 0
        for tgd in tgids.values():
            if rate_comm in tgd['name']:
                p += 1
            for pd in tgd['pids'].values():
                f = False
                for sd in pd.values():
                    if sd['label'] == 1:
                        if rate_comm in tgd['name']:
                            tp += 1
                        else:
                            fp += 1
                        f = True
                        break
                if f:
                    break
        print("recall:%f%% precision:%f%%" % (tp/p*100 if p else 0, tp/(tp+fp)*100 if tp+fp else 0))

def int_handler(sig, frame):
    print("\b\bquit...")
    b.detach_perf_event(ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.CPU_CLOCK)
    # system("tput rmcup")
    with open("stack_count.log", "w") as file:
        format_put(file=file, rate_comm='stress-ng', anomaly_detect=True)
    exit()

signal(2, int_handler)
signal(1, int_handler)
# system("tput -x smcup; clear")
while 1:
    sleep(5)
    log()