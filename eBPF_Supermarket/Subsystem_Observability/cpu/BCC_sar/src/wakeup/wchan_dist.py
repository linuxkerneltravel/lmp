import psutil

if __name__ == "__main__":
    pids = psutil.pids()
    wchanMap = {}
    for pid in pids:
        with open("/proc/{}/wchan".format(pid), "r") as f:
            wchan = f.read()
        if wchan in wchanMap:
            wchanMap[wchan].append(pid)
        else:
            wchanMap[wchan] = [pid]
    for key in wchanMap.keys():
        print("%40s %d" % (key, len(wchanMap[key])))