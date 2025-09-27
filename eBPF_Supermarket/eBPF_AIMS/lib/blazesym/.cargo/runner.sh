#!/bin/sh

# Eliminate as much background work as possible by flushing caches that
# could cause IO and with that background work that may disturb the system.
sync
echo 3 > /proc/sys/vm/drop_caches

# Niceness adjustments are mostly done for benchmarking.
nice --adjustment=-20 ionice --class=realtime "$@"
