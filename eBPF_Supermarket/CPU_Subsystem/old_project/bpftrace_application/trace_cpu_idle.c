#!/bin/bpftrace

tracepoint:power:cpu_idle {
    @h[args->state] += 1;
}