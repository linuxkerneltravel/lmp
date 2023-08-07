#!/bin/python
from my_format import *
from signal import signal, SIG_IGN
from time import sleep
from bcc import BPF, PerfType, PerfSWConfig
from argparse import ArgumentTypeError, ArgumentParser, RawDescriptionHelpFormatter, SUPPRESS
from subprocess import Popen, PIPE

mode_list = ['on_cpu', 'off_cpu', 'mem']

# arguments
examples = """examples:
    sudo -E ./stack_count.py             # trace on-CPU stack time until Ctrl-C
    sudo -E ./stack_count.py -m off_cpu  # trace off-CPU stack time until Ctrl-C
    sudo -E ./stack_count.py 5           # trace for 5 seconds only
    sudo -E ./stack_count.py -f 5        # 5 seconds, and output as stack_count.svg in flame graph format
    sudo -E ./stack_count.py -s 5        # 5 seconds, and show symbol offsets
    sudo -E ./stack_count.py -p 185      # only trace threads for PID 185
    sudo -E ./stack_count.py -t 188      # only trace thread 188
    sudo -E ./stack_count.py -c cmdline  # only trace threads of cmdline
    sudo -E ./stack_count.py -u          # only trace user threads (no kernel)
    sudo -E ./stack_count.py -k          # only trace kernel threads (no user)
    sudo -E ./stack_count.py -U          # only show user space stacks (no kernel)
    sudo -E ./stack_count.py -K          # only show kernel space stacks (no user)
    sudo -E ./stack_count.py -a          # anomaly detection for stack
"""


def positive_int(val:str):
    try:
        ival = int(val)
    except ValueError:
        raise ArgumentTypeError("must be an integer")
    if ival <= 0:
        raise ArgumentTypeError("must be positive")
    return ival

def mode_str(val:str):
    if val in mode_list:
        return val
    else:
        raise ArgumentTypeError("must be 'on_cpu', 'off_cpu' or 'mem'")


parser = ArgumentParser(
    description="Summarize on-CPU time by stack trace",
    formatter_class=RawDescriptionHelpFormatter,
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


parser.add_argument("-a", "--auto", action="store_true",
                    help="analyzing stacks automatically")
parser.add_argument("-d", "--delimited", action="store_true",
                    help="insert delimiter between kernel/user stacks")
parser.add_argument("-f", "--folded", action="store_true",
                    help="output folded format")
parser.add_argument("-s", "--offset", action="store_true",
                    help="show address offsets")
parser.add_argument("-m", "--mode", default='on_cpu',
                    type = mode_str,
                    help="mode of stack counting, 'on_cpu'/'off_cpu'/'mem'")
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
                    help=SUPPRESS)
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)
mode = args.mode
debug = 0

# set thread filter
pid = -1
thread_context = ""
thread_filter = 'curr->pid'
if args.tgid is not None:
    # thread_filter = '!(curr->tgid == %d)' % args.tgid
    pid = args.tgid
    thread_context = "PID " + str(pid)
    if mode == 'off_cpu':
        thread_filter = 'curr->tgid == %d' % pid
elif args.pid is not None:
    thread_context = "TID %d" % args.pid
    thread_filter = 'curr->pid == %d' % args.pid
    pid = args.pid
elif args.cmd is not None:
    cmd = args.cmd.split()
    ps = Popen(cmd)
    ps.send_signal(19)
    pid = ps.pid
    thread_context = "PID " + str(pid)
    if mode == 'off_cpu':
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
from sys import path
with open(path[0]+'/'+mode+'_count.bpf.c', encoding='utf-8') as f:
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
    from sys import stderr
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

auto = False
if args.auto:
    auto = True
    from my_ad import adc
    ado = adc()


ad = False
if auto and not args.pid and not args.tgid and not args.cmd:
    ad = True

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
    case 'mem':
        arch = Popen(args='uname -m', stdout=PIPE, shell=True).stdout.read().decode().split()[0]
        lib = "/usr/lib/"+arch+"-linux-gnu/libc.so.6"
        # if pid != -1:
        #     from psutil import Process
        #     lib = Process(pid).exe()
        b.attach_uprobe(name=lib, sym='malloc', fn_name='malloc_enter', pid=pid)
        b.attach_uretprobe(name=lib, sym='malloc', fn_name='malloc_exit', pid=pid)
        b.attach_uprobe(name=lib, sym='free', fn_name='free_enter', pid=pid)


if pid != -1:
    print("attach %d." % pid)
    # add external sym
    try:
        from psutil import Process
        b.add_module(Process(pid).exe())
    except:
        print("failed to load syms of pid %d" % pid)
else:
    print("attach all processes")


def int_handler(sig=None, frame=None):
    print("\b\bquit...")
    match mode:
        case 'on_cpu':
            b.detach_perf_event(ev_type=PerfType.SOFTWARE,
                                ev_config=PerfSWConfig.CPU_CLOCK)
        case 'off_cpu':
            for tp in b.get_kprobe_functions(b"^finish_task_switch$|^finish_task_switch\.isra\.\d$"):
                b.detach_kprobe(tp)
        case 'mem':
            try:
                b.detach_uprobe(lib, 'malloc')
                b.detach_uretprobe(lib, 'malloc')
                b.detach_uprobe(lib, 'free')
            except:
                pass
    
    # system("tput rmcup")
    if auto:
        if not ad:
            ado.auto_label(b)
        ado.avg_mutant()
        get_mutant = ado.get_mutant
    else:
        get_mutant = lambda _:0

    tgids = map2dict(b, get_mutant, need_delimiter, show_offset)
    print("save to stack_count.json...")
    with open("stack_count.json", "w") as file:
        file.write(dumps(tgids, cls=MyEncoder, indent=2, ensure_ascii=True,
                         sort_keys=False, separators=(',', ':')))
    if auto:
        print("calc ad performance...")
        from my_ad import rate
        from re import match
        rate(tgids, lambda x: match(r'stress-ng-.*', x))
    if folded:
        print("save to stack_count.svg...")
        fla_text(b, need_delimiter)
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
        if ad:
            ado.ad_log(b)
    signal(2, SIG_IGN)
    signal(1, SIG_IGN)
    ps.kill()
    int_handler()
else:
    signal(2, int_handler)
    signal(1, int_handler)
    for _ in range(duration//5):
        sleep(5)
        if ad:
            ado.ad_log(b)
    signal(2, SIG_IGN)
    signal(1, SIG_IGN)
    int_handler()
