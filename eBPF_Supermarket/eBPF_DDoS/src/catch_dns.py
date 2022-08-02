from bcc import BPF
from threading import Thread
import time
import ctypes
import constants


def clean_map(config, counter):
    while 1:
        seconds = config.get(
            config.Key(constants.INTERVAL_KEY), default=ctypes.c_uint32(60)
        ).value
        time.sleep(seconds)

        fail_threshold = config.get(
            config.Key(constants.FAILURE_THRESHOLD_KEY), default=ctypes.c_uint32(65535)
        ).value
        count_threshold = config.get(
            config.Key(constants.COUNT_THRESHOLD_KEY), default=ctypes.c_uint32(65535)
        ).value
        any_threshold = config.get(
            config.Key(constants.ANY_THRESHOLD_KEY), default=ctypes.c_uint32(65535)
        ).value

        for ip, record in counter.items():
            if (
                record.fail_count < fail_threshold
                and record.count < count_threshold
                and record.any_count < any_threshold
            ):
                del counter[ip]


b = BPF(src_file="catch_dns.c")
sk_filter = b.load_func("catch_dns", BPF.SOCKET_FILTER)

# TODO: make it configurable
interface = "eth0"
BPF.attach_raw_socket(sk_filter, interface)

# start cleaner
configuration = b.get_table("configuration")
counter = b.get_table("counter")
cleaner = Thread(target=clean_map, kwargs={"config": configuration, "counter": counter})
cleaner.start()

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%s" % (msg))
