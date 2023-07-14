#!/bin/python
from bcc import BPF, PerfType, PerfSWConfig
from sys import stderr
from time import sleep
from psutil import Process
from pyod.models.knn import KNN
# from pyod.models.lof import LOF
# from pyod.models.cblof import CBLOF
# from pyod.models.loci import LOCI
# from pyod.models.abod import ABOD
# from pyod.models.hbos import HBOS
# from pyod.models.sos import SOS
# from pyod.models.deep_svdd import DeepSVDD
from json import dumps, JSONEncoder
from signal import signal, SIG_IGN
import argparse
from subprocess import Popen
# from pyod.models.deep_svdd import DeepSVDD
clf_name = 'KNN'
clf = KNN()
mode = 'on_cpu'

# arguments
examples = """examples:
    sudo -E ./stack_count.py             # trace on-CPU stack time until Ctrl-C
    sudo -E ./stack_count.py 5           # trace for 5 seconds only
    sudo -E ./stack_count.py -f 5        # 5 seconds, and output in folded format
    sudo -E ./stack_count.py -s 5        # 5 seconds, and show symbol offsets
    sudo -E ./stack_count.py -p 185      # only trace threads for PID 185
    sudo -E ./stack_count.py -t 188      # only trace thread 188
    sudo -E ./stack_count.py -c cmdline  # only trace threads of cmdline
    sudo -E ./stack_count.py -u          # only trace user threads (no kernel)
    sudo -E ./stack_count.py -k          # only trace kernel threads (no user)
    sudo -E ./stack_count.py -U          # only show user space stacks (no kernel)
    sudo -E ./stack_count.py -K          # only show kernel space stacks (no user)
"""


def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if ival <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival


parser = argparse.ArgumentParser(
    description="Summarize on-CPU time by stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
# Note: this script provides --pid and --tid flags but their arguments are
# referred to internally using kernel nomenclature: TGID and PID.
thread_group.add_argument("-p", "--pid", metavar="PID", dest="tgid",
                          help="trace this PID only", type=positive_int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="pid",
                          help="trace this TID only", type=positive_int)
thread_group.add_argument("-c", "--cmd", metavar="Command", dest='cmd',
                          help="trace this command only", type=str)
thread_group.add_argument("-u", "--user-threads-only", action="store_true",
                          help="user threads only (no kernel threads)")
thread_group.add_argument("-k", "--kernel-threads-only", action="store_true",
                          help="kernel threads only (no user threads)")

stack_group = parser.add_mutually_exclusive_group()
stack_group.add_argument("-U", "--user-stacks-only", action="store_true",
                         help="show stacks from user space only (no kernel space stacks)")
stack_group.add_argument("-K", "--kernel-stacks-only", action="store_true",
                         help="show stacks from kernel space only (no user space stacks)")
parser.add_argument("-d", "--delimited", action="store_true",
                    help="insert delimiter between kernel/user stacks")
parser.add_argument("-f", "--folded", action="store_true",
                    help="output folded format")
parser.add_argument("-s", "--offset", action="store_true",
                    help="show address offsets")
parser.add_argument("--stack-storage-size", default=16384,
                    type=positive_int,
                    help="the number of unique stack traces that can be stored and "
                    "displayed (default 16384)")
parser.add_argument("duration", nargs="?", default=99999999,
                    type=positive_int,
                    help="duration of trace, in seconds")
parser.add_argument("--state", type=positive_int,
                    help="filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE" +
                    ") see include/linux/sched.h")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)
debug = 0

# set thread filter
pid = -1
thread_context = ""
thread_filter = 'curr->pid'
if args.tgid is not None:
    # thread_filter = '!(curr->tgid == %d)' % args.tgid
    pid = args.tgid
    thread_context = "PID " + str(pid)
    if mode != 'on_cpu':
        thread_filter = 'curr->tgid == %d' % pid
elif args.pid is not None:
    thread_context = "TID %d" % args.pid
    thread_filter = 'curr->pid == %d' % args.pid
    pid = [args.pid]
elif args.cmd is not None:
    ps = Popen(args.cmd, shell=True)
    ps.send_signal(19)
    pid = ps.pid
    thread_context = "PID " + str(pid)
    if mode != 'on_cpu':
        thread_filter = 'curr->tgid == %d' % pid
    # perf default attach children process
elif args.user_threads_only:
    thread_context = "user threads"
    thread_filter += ' && curr->flags & PF_KTHREAD'
elif args.kernel_threads_only:
    thread_context = "kernel threads"
    thread_filter += ' && curr->flags & PF_KTHREAD'
else:
    thread_context = "all threads"

if args.state == 0:
    state_filter = 'curr->STATE_FIELD == 0'
elif args.state:
    # these states are sometimes bitmask checked
    state_filter = 'curr->STATE_FIELD & %d' % args.state
else:
    state_filter = '1'

# stack data ebpf code
with open(mode+'_count.bpf.c', encoding='utf-8') as f:
    bpf_text = f.read()

bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)
bpf_text = bpf_text.replace('STATE_FILTER', state_filter)

if BPF.kernel_struct_has_field(b'task_struct', b'__state') == 1:
    bpf_text = bpf_text.replace('STATE_FIELD', '__state')
else:
    bpf_text = bpf_text.replace('STATE_FIELD', 'state')

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

# handle stack args
kernel_stack_get = "stack_trace.get_stackid(ctx, 0)"
user_stack_get = "stack_trace.get_stackid(ctx, BPF_F_USER_STACK)"
stack_context = ""
if args.user_stacks_only:
    stack_context = "user"
    kernel_stack_get = "-1"
elif args.kernel_stacks_only:
    stack_context = "kernel"
    user_stack_get = "-1"
else:
    stack_context = "user + kernel"
bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
bpf_text = bpf_text.replace('KERNEL_STACK_GET', kernel_stack_get)

need_delimiter = args.delimited and not (args.kernel_stacks_only or
                                         args.user_stacks_only)

if args.kernel_threads_only and args.user_stacks_only:
    print("ERROR: Displaying user stacks for kernel threads " +
          "doesn't make sense.", file=stderr)
    exit(2)

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        print("ERROR: Exiting")
        exit(3)

if args.folded and args.offset:
    print("ERROR: can only use -f or -s. Exiting.")
    exit()

show_offset = False
if args.offset:
    show_offset = True

# bpf parsing
b = BPF(text=bpf_text)
print("eBPF initializing compelete.")
match mode:
    case 'on_cpu':
        b.attach_perf_event(ev_type=PerfType.SOFTWARE,
                            ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_stack",
                            sample_period=0, sample_freq=99, pid=pid)
    case 'off_cpu':
        b.attach_kprobe(
            event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$", fn_name='do_stack')

if pid != -1:
    print("attach %d." % pid)
    # add external sym
    try:
        b.add_module(Process(pid).exe())
    except:
        print("failed to load syms of pid %d" % pid)
else:
    print("attach all processes")


def log():
    psid_count = {psid_t(psid): n.value for psid, n in b["psid_count"].items()}
    count = [[n] for n in psid_count.values()]
    try:
        clf.fit(count)
        labels = clf.labels_
        for (spid, n), label in zip(psid_count.items(), labels):
            print('pid:%6d\tsid:(%6d,%6d)\tcount:%-6d\tlabel:%d' %
                  (spid.pid, spid.ksid, spid.usid, n, label))
    except:
        pass


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
        self.ksid = psid.ksid
        self.usid = psid.usid


max_deep = 0


def get_deep(usid):
    if (usid < 0):
        return 0
    global max_deep
    deep = 0
    for _ in stack_trace.walk(usid):
        deep += 1
    if deep > max_deep:
        max_deep = deep
    return deep


def fla_text():
    global max_deep
    max_deep = 0
    psid_count = {psid_t(psid): count.value for psid,
                  count in b["psid_count"].items()}
    deeps = [get_deep(psid.usid) for psid in psid_count.keys()]
    lines = ''
    for (psid, count), deep in zip(psid_count.items(), deeps):
        lines += ''.join(
            (
                [
                    "%s\n" % (b.ksym(j).decode())
                    for j in stack_trace.walk(psid.ksid)
                ] if psid.ksid >= 0 else []
            ) + (
                ['-'*32+'\n'] if need_delimiter else []
            ) + (
                [
                    "%s\n" % (b.sym(j, psid.pid).decode())
                    for j in stack_trace.walk(psid.usid)
                ] + ['.\n'*(max_deep-deep)]
                if psid.usid >= 0 else []
            ) + [
                str(count) + '\n'*2
            ]
        )
    with open("stack_count.stk", "w") as file:
        file.write(lines)


def ad_json(rate_comm: str = None, anomaly_detect=False, flame_format=False):
    psid_count = {psid_t(psid): count.value for psid,
                  count in b["psid_count"].items()}
    tgid_comm = {tgid.value: comm.str.decode()
                 for tgid, comm in b["tgid_comm"].items()}
    pid_tgid = {pid.value: tgid.value for pid, tgid in b["pid_tgid"].items()}

    tgids = {
        tgid: {
            'name': comm,
            'pids': dict()
        } for tgid, comm in tgid_comm.items()
    }
    count = [[n] for n in psid_count.values()]
    labels = dict()
    if anomaly_detect:
        try:
            clf.fit(count)
            labels = clf.labels_.astype(int).tolist()
        except:
            pass
    if labels == dict():
        labels = [None for i in range(len(count))]

    for (psid, n), label in zip(psid_count.items(), labels, strict=True):
        pid_d = tgids[pid_tgid[psid.pid]]['pids'].setdefault(psid.pid, dict())
        pid_d[str(psid.ksid)+','+str(psid.usid)] = {
            'trace': (
                (
                    [
                        "%#08x:%s" % (j, b.ksym(j).decode())
                        for j in stack_trace.walk(psid.ksid)
                    ] if psid.ksid >= 0
                    else ['[Missed Kernel Stack]']
                ) + (
                    ['-'*50] if need_delimiter
                    else []
                ) + (
                    [
                        "%#08x:%s" % (
                            j, b.sym(j, psid.pid, show_offset=show_offset).decode())
                        for j in stack_trace.walk(psid.usid)
                    ] if psid.usid >= 0
                    else ['[Missed User Stack]']
                )
            ),
            'count': n,
            'label': label
        }
    with open("stack_count.json", "w") as file:
        file.write(dumps(tgids, cls=MyEncoder, indent=2, ensure_ascii=True,
                         sort_keys=False, separators=(',', ':')))

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
        print("%s recall:%f%% precision:%f%%" %
              (rate_comm, tp/p*100 if p else 0, tp/(tp+fp)*100 if tp+fp else 0))


def int_handler(sig=None, frame=None):
    print("\b\bquit...")
    if mode == 'on_cpu':
        b.detach_perf_event(ev_type=PerfType.SOFTWARE,
                            ev_config=PerfSWConfig.CPU_CLOCK)
    # system("tput rmcup")
    print("save to stack_count.json...")
    ad_json(rate_comm='stress-ng-cpu', anomaly_detect=True)
    if folded:
        print("save to stack_count.stk...")
        fla_text()
    exit()


# system("tput -x smcup; clear")
if args.cmd != None:
    signal(2, lambda *_: ps.kill)
    signal(1, lambda *_: ps.kill)
    ps.send_signal(18)
    d = 0
    while ps.poll() == None and d <= duration:
        sleep(5)
        d += 5
        log()
    signal(2, SIG_IGN)
    signal(1, SIG_IGN)
    ps.kill()
    int_handler()
else:
    signal(2, int_handler)
    signal(1, int_handler)
    for _ in range(duration//5):
        sleep(5)
        log()
    signal(2, SIG_IGN)
    signal(1, SIG_IGN)
    int_handler()
