import re, os

# print a cint_list(list of ctypes variable)
def printList(cint_list):
    for i in cint_list:
        print(i.value, end=",")
    print()

# get the number of the count of cpus
# @return int
def get_num_cpus() -> int:
    num_cpus = 1
    with open("/proc/cpuinfo", "r") as f:
        while True:
            s = f.readline()
            if not s: break
            if re.match("^processor\t: [0-9]+\n$", s):
                num_cpus = int(s[:-1].split(" ")[-1]) + 1
    return num_cpus

# find ksymbol in /proc/kallsyms
# if find, return a positive number, else negative.
# @return int
def find_ksym(ksym: str) -> int:
    addr = -1
    with open("/proc/kallsyms", 'r') as f:
        line = f.readline()
        while line:
            if line[:-1].endswith(" " + ksym):
                addr = line.split(" ")[0]
                break
            line = f.readline()
    return addr

class SecondRecord:
    def __init__(self, initval=0) -> None:
        self.val = initval

    # update and read delta
    def UpRd(self, val):
        dta = val - self.val
        self.val = val
        return dta

def get_pid_by_name(name: str) -> int:
    f = os.popen("ps -A | grep ' " + name + "$" + "'")
    lines = f.readlines()
    if len(lines) != 1:
        return -1
    else:
        f_str = lines[0]

    pid = re.match(" *([0-9]+) ", f_str).group(0)
    pid = int(pid)
    return pid