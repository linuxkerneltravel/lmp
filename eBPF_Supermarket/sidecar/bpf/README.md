# BPF

## Intro

This directory is all about BPF programs and management. It includes:

- [TCP Accept Event Probe](tcpaccept): captures TCP accept event information. With time, pid, address and port information.
- [TCP Connect Event Probe](tcpconnect): captures TCP connect event information. With time, pid, address and port information.
- [TCP Close Event Probe](tcpclose): captures TCP close event information. With basic info and traffic statistics.
- [Network Subsystem Probe](podnet): traces key network event in host, for most scenarios in this project, network stack events around the pod.
- [TCP Socket Redirect](sockops): attaches sockops and SK_MSG programs to **cgroup v2**, and redirect local TCP connection (both sidecar and pods on the same host) to bypass TCP/IP protocol stack.
- [BPF Header Files](headers): provides minimal BPF dependency header files, in order to compile

For most probes, they can filter by process id, and notify you by Go channel.

For functional BPF programs, they can run in the background, until a termination signal is received.

## BFP Develop Guide

### Performance event BPF programs

For scalability reasons, development based on [BCC](https://github.com/iovisor/bcc) and [gobpf](https://github.com/iovisor/gobpf) library.

1. Define event struct for both C and Go. For network tracing, maybe you have to provide both IPv4 and IPv6 versions.
2. Write your tracing code by C, which must match the argument list.
3. Insert filter policy code dynamically. Filtering by pid is the most frequently used policy.
4. Attach your code to instrumentation point.
5. Initialize your event map, and got its Go channel.
6. Start a goroutine and wait for event to happen.
7. Process the event struct to user-friendly format and submit to the upper caller.

### Functional BPF programs

For functional and performance reasons, Go library [github.com/cilium/ebpf](https://github.com/cilium/ebpf) is used for implementation.

1. Write BPF C programs, and define relevant maps.
2. Use `bpf2go` tool to generate BPF byte code and Go file from C code. Usually use a go generate command at the top of the Go file.
3. Load all programs and maps via interface in generated Go files.
4. Pass information of the upper-level to the maps. (optional)
5. Attach the BPF programs to specified position.
6. Define unload and unpin logic for detaching BPF programs.

## Hints

To develop BPF program in Go, here are some best practices hints. Maybe they are useful for you.

1. Keep your event struct **aligned in 8 byte**. Compiler always do some unknowable things when we write not aligned code. For some time, the compiler of C and the compiler of Go organize your struct differently. And, when you read binary data from C to Go, they will come out and make trouble. So, keep your data structure aligned to avoid it.
2. Use `/*FILTER*/` as placeholder for inserting filter code. That can make sure your code can work even if you don't provide filter code.
3. In [iovisor/bcc@ffff0ed](https://github.com/iovisor/bcc/commit/ffff0edc00ad249cffbf44d855b15020cc968536), `bcc_func_load`'s signature was changed. However, [gobpf](https://github.com/iovisor/gobpf) still lacks of maintenance on this. So, we should change the library as [this PR](https://github.com/iovisor/gobpf/pull/311). As a workaround, we extracted this as a [new library](https://github.com/ESWZY/gobpf/tree/0.24.0), and just need use `replace` directive `replace github.com/iovisor/gobpf => github.com/eswzy/gobpf v0.2.1-0.20220720201619-9eb793319a76` in `go.mod` file (after `go get github.com/eswzy/gobpf@0.24.0`).
4. For functional BPF programs, encapsulate load, attach and unload functions respectively. The specific behaviors should be implemented in user mode.

## See Also

[BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)

[eBPF Mistake Avoidance Guide (blog in Chinese)](https://segmentfault.com/a/1190000041179276)
