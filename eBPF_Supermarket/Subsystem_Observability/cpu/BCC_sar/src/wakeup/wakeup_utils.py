# demo: stack_str = get_sleep_func(bpf, stackid);
# get_sleep_func 从睡眠栈中提取出能代表睡眠原因的函数，并返回
def get_sleep_func(bpf, stackid)-> str:
    # 直接打印整个栈的信息
    # stack_str = ""
    # for addr in bpf["stacktraces"].walk(stackid):
    #     sym = bpf.ksym(addr).decode('utf-8', 'replace')
    #     stack_str = stack_str + "\t" + sym + "\n"

    find_schedule = 0
    for addr in bpf["stacktraces"].walk(stackid):
        sym = bpf.ksym(addr).decode('utf-8', 'replace')
        if "schedule" in sym and find_schedule == 0:
            find_schedule = 1
        elif "schedule" not in sym and find_schedule == 1:
            stack_str = sym
            break
    return stack_str

# 方便的管理数据随时间的更改，并能计算变化量
class deltaTimeMgr:
    def __init__(self, cnt: int) -> None:
        self.container = [0 for _ in range(cnt)]
        self.delta = [0 for _ in range(cnt)]
        self.cnt = cnt

    def update(self, lst) -> list:
        if len(lst) != self.cnt:
            raise Exception("列表长度不匹配")
        else:
            for i in range(len(lst)):
                self.delta[i] = lst[i] - self.container[i]
                self.container[i] = lst[i]
            return self.delta

# 管理一个测量值的列表，并提供取平均值和清空的功能
class MetricsAverager:
    def __init__(self) -> None:
        self.lst = []
        pass

    def add(self, metric):
        self.lst.append(metric)

    def average(self):
        sum = 0.0
        for i in self.lst:
            sum += i
        if len(self.lst) != 0:
            return sum / len(self.lst)
        else:
            return 0

    def recent(self):
        if len(self.lst) == 0:
            return 0
        else:
            return self.lst[-1]

    def clear(self):
        self.lst.clear()