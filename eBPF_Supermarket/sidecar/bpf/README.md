# BPF

## Intro

This directory is all about BPF programs and management. It includes:

- [TP Accept Event Probe](tcpaccept): To capture TCP accept information. With time, pid, address and port information.
- [TP Connect Event Probe](tcpconnect): To capture TCP connect information. With time, pid, address and port information.

For most probes, they can filter by process id, and notify you by Go channel.

## BFP Develop Guide

1. Define event struct for both C and Go. For network tracing, maybe you have to provide both IPv4 and IPv6 versions.
2. Write your tracing code by C, which must match the argument list.
3. Insert filter policy code dynamically. Filtering by pid is the most frequently used policy.
4. Attach your code to instrumentation point.
5. Initialize your event map, and got its Go channel.
6. Start a goroutine and wait for event to happen.
7. Process the event struct to user-friendly format and submit to the upper caller.

## Hints

To develop BPF program in Go, here are some best practices hints. Maybe they are useful for you.

1. Keep your event struct *aligned in 8 byte*. Compiler always do some unknowable things when we write not aligned code. For some time, the compiler of C and the compiler of Go organize your struct differently. And, when you read binary data from C to Go, they will come out and make trouble. So, keep your data structure aligned to avoid it.
2. Use `/*FILTER*/` as placeholder for inserting filter code. That can make sure your code can work even if you don't provide filter code.

## See Also

[BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)

[eBPF Mistake Avoidance Guide (blog in Chinese)](https://segmentfault.com/a/1190000041179276)
