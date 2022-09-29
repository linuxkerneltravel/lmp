import sys
from bcc import BPF
from threading import Thread
import time
import os
import logging
import ctypes
import constants


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)


def clean_map(config, counter, metrics):
    amplification = False
    nxdomain = False

    while 1:
        seconds = config.get(
            config.Key(constants.INTERVAL_KEY), default=ctypes.c_uint32(60)
        ).value
        time.sleep(seconds)

        fail_threshold = config.get(
            config.Key(constants.FAILURE_THRESHOLD_KEY),
            default=ctypes.c_uint32(4294967295),
        ).value
        count_threshold = config.get(
            config.Key(constants.COUNT_THRESHOLD_KEY),
            default=ctypes.c_uint32(4294967295),
        ).value
        any_threshold = config.get(
            config.Key(constants.ANY_THRESHOLD_KEY), default=ctypes.c_uint32(4294967295)
        ).value
        global_any_threshold = config.get(
            config.Key(constants.GLOBAL_ANY_THRESHOLD_KEY),
            default=ctypes.c_uint32(4294967295),
        ).value
        global_fail_threshold = config.get(
            config.Key(constants.GLOBAL_FAIL_THRESHOLD_KEY),
            default=ctypes.c_uint32(4294967295),
        ).value

        qsize = metrics.get(
            metrics.Key(constants.REQUEST_SIZE_KEY),
            default=ctypes.c_uint64(0),
        ).value
        rsize = metrics.get(
            metrics.Key(constants.RESPONSE_SIZE_KEY),
            default=ctypes.c_uint64(0),
        ).value

        resp_time = metrics.get(
            metrics.Key(constants.RESPONSE_TIME_KEY),
            default=ctypes.c_uint64(65535),
        ).value

        metrics[metrics.Key(constants.REQUEST_SIZE_KEY)] = ctypes.c_uint64(0)
        metrics[metrics.Key(constants.RESPONSE_SIZE_KEY)] = ctypes.c_uint64(0)
        metrics[metrics.Key(constants.RESPONSE_TIME_KEY)] = ctypes.c_uint64(0)

        for ip, record in counter.items():
            if ip.value == constants.GLOBAL_IP:
                a = 0
                if record.any_count < global_any_threshold or not amplification:
                    a = record.any_count

                if record.any_count < global_any_threshold:
                    record.any_count = 0
                    amplification = False
                else:
                    amplification = True

                f = record.fail_count
                if f < global_fail_threshold:
                    nxdomain = False
                else:
                    nxdomain = True

                cnt = record.count
                if cnt > 0:
                    if amplification:
                        logging.warning(
                            "under amplification attack!!! stats in {}s: fail_count: {}({:.2%}), any_count: {}({:.2%}), total_count: {}, avg_response_time: {:.2}ms, amplification_factor: {:.2%}".format(
                                seconds,
                                f,
                                f / cnt,
                                a,
                                a / cnt,
                                cnt,
                                resp_time / cnt / 1e6,
                                rsize / qsize,
                            ),
                        )
                    elif nxdomain:
                        logging.warning(
                            "under nxdomain attack!!! stats in {}s: fail_count: {}({:.2%}), any_count: {}({:.2%}), total_count: {}, avg_response_time: {:.2}ms, amplification_factor: {:.2%}".format(
                                seconds,
                                f,
                                f / cnt,
                                a,
                                a / cnt,
                                cnt,
                                resp_time / cnt / 1e6,
                                rsize / qsize,
                            ),
                        )
                    else:
                        logging.info(
                            "stats in {}s: fail_count: {}({:.2%}), any_count: {}({:.2%}), total_count: {}, avg_response_time: {:.2}ms, amplification_factor: {:.2%}".format(
                                seconds,
                                f,
                                f / cnt,
                                a,
                                a / cnt,
                                cnt,
                                resp_time / cnt / 1e6,
                                rsize / qsize,
                            ),
                        )

                record.fail_count = 0
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

interface = os.getenv(constants.DDOS_INTERFACE,default="eth0")
BPF.attach_raw_socket(sk_filter, interface)

# start cleaner
configuration = b.get_table("configuration")
counter = b.get_table("counter")
metrics = b.get_table("metrics")

cleaner = Thread(
    target=clean_map,
    kwargs={"config": configuration, "counter": counter, "metrics": metrics},
)
cleaner.start()

print("started!")
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%s" % (msg))
