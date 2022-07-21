from bcc import BPF
from threading import Thread
import time

def clean_map(m):
    while 1:
        seconds=10
        try:
            seconds = m[m.Key(4294967295)].value
        except KeyError:
            pass

        if seconds==0:
            seconds=10
        time.sleep(seconds)
        
        threshold = 0
        try:
            threshold = m[m.Key(0)]
        except KeyError:
            pass
        
        if threshold==0:
            m.clear()

        ips_to_delete = []
        for ip, count in m.items():
            if count.value < threshold.value and ip.value != 0 and ip.value != 4294967295:
               del m[ip]

b = BPF(src_file="catch_dns.c")
sk_filter = b.load_func("catch_dns", BPF.SOCKET_FILTER)

# TODO: make it configurable
interface="eth0"
BPF.attach_raw_socket(sk_filter, interface)

fail_counter = b.get_table("fail_counter")
cleaner = Thread(target=clean_map, kwargs={'m': fail_counter})
cleaner.start()

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%s" % (msg))
