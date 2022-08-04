import sys
from bcc import BPF
from threading import Thread
import time
import logging
import ctypes
import constants


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)


def clean_map(config, counter):
    amplification = False
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
        global_any_threshold = config.get(
            config.Key(constants.GLOBAL_ANY_THRESHOLD_KEY),
            default=ctypes.c_uint32(65535),
        ).value

        for ip, record in counter.items():
            if ip.value == constants.GLOBAL_IP:
                a = 0
                if record.any_count < global_any_threshold or not amplification:
                    a = record.any_count
                f = record.fail_count
                t = record.count

                if record.any_count < global_any_threshold:
                    record.any_count = 0
                    amplification = False
                else:
                    amplification = True

                if t > 0:
                    if amplification:
                        logging.warning(
                            "under amplification attack!!! stats in {}s: fail_count: {}({:.2%}), any_count: {}({:.2%}), total_count: {}".format(
                                seconds, f, f / t, a, a / t, t
                            ),
                        )
                    else:
                        logging.info(
                            "stats in {}s: fail_count: {}({:.2%}), any_count: {}({:.2%}), total_count: {}".format(
                                seconds, f, f / t, a, a / t, t
                            ),
                        )

                record.count = 0
                counter[ip] = record
            elif (
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

print("started")
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%s" % (msg))
