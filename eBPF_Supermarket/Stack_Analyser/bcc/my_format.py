from my_class import *


def map2dict(b, get_mutant: callable, need_delimiter=True, show_offset=False) -> dict:
    psid_count = {psid_t(psid): count.value for psid,
                  count in b["psid_count"].items()}
    pid_comm = {pid.value: comm.str.decode()
                for pid, comm in b["pid_comm"].items()}
    pid_tgid = {pid.value: tgid.value for pid, tgid in b["pid_tgid"].items()}
    stack_trace = b["stack_trace"]

    tgids = dict()
    for pid, tgid in pid_tgid.items():
        tgid_d = tgids.setdefault(tgid, dict())
        tgid_d[pid] = {'name': pid_comm[pid]}

    for psid, n in psid_count.items():
        stks_d = tgids[pid_tgid[psid.pid]
                       ][psid.pid].setdefault('stacks', dict())
        stks_d[str(psid.ksid)+','+str(psid.usid)] = {
            'trace': (
                (["%#08x:%s" % (j, b.ksym(j).decode())
                  for j in stack_trace.walk(psid.ksid)] if psid.ksid >= 0 else ['[Missed Kernel Stack]']) +
                (['-'*50] if need_delimiter else []) +
                (["%#08x:%s" % (j, b.sym(j, psid.pid, show_offset=show_offset).decode())
                 for j in stack_trace.walk(psid.usid)] if psid.usid >= 0 else ['[Missed User Stack]'])
            ), 'count': n, 'label': get_mutant(psid)
        }
    return tgids


def fla_text(b, need_delimiter):
    psid_count = {psid_t(psid): count.value for psid,
                  count in b["psid_count"].items()}
    stack_trace = b["stack_trace"]

    def get_deep(stack_trace, usid):
        if (usid < 0):
            return 0
        deep = 0
        for _ in stack_trace.walk(usid):
            deep += 1
        return deep

    deeps = [get_deep(stack_trace, psid.usid) for psid in psid_count.keys()]
    max_deep = 0
    for deep in deeps:
        if max_deep < deep:
            max_deep = deep
    lines = ''
    for (psid, count), deep in zip(psid_count.items(), deeps, strict=True):
        lines += ''.join(
            (["%s\n" % (b.ksym(j).decode()) 
              for j in stack_trace.walk(psid.ksid)] if psid.ksid >= 0 else []) +
            (['-'*32+'\n'] if need_delimiter else []) +
            (["%s\n" % (b.sym(j, psid.pid, show_module=True).decode()) 
              for j in stack_trace.walk(psid.usid)] if psid.usid >= 0 else []) +
            ['.\n'*(max_deep - deep)] +
            [str(count) + '\n'*2]
        )
    with open("stack_count.stk", 'w') as file:
        file.write(lines)
    with open("stack_count.svg", "w") as file:
        from subprocess import Popen, PIPE
        fle = Popen("FlameGraph/stackcollapse.pl | FlameGraph/flamegraph.pl",
                    shell=True, stdin=PIPE, stdout=file)
        fle.stdin.write(lines.encode())
        fle.stdin.close()
        fle.wait()
        file.flush()
