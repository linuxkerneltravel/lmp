---
layout: post
title: solisten
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall]
summary: solisten traces IPv4 and IPv6 listen syscalls, and prints various details.
---

## origin

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/solisten.bpf.c

result:

```console
$ sudo ecli/build/bin/Release/ecli run examples/bpftools/solisten/package.json

running and waiting for the ebpf events from perf event...
Unsupported type: __u32[4] [4 x i32]
time pid proto backlog ret port task
```

## Compile and Run

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run examples/bpftools/solisten/package.json
```

## details in bcc

Demonstrations of solisten, the Linux eBPF/bcc version.


solisten traces IPv4 and IPv6 listen syscalls, and prints various details.

Example trigger:
```console
#nc -lp 23 &
time pid proto backlog ret port task 
20:17:52 6528 131073 1 0 23 nc 
20:17:52 6528 131073 1 0 23 nc
^C
```

netcat (nc for short) is a simple but powerful network command-line tool for performing any operation related to TCP, UDP, or Unix sockets in Linux.

nc can be used for port scanning, port redirection, starting port listeners; It can also be used to open remote connections and many other things.

nc -lp 23 &//use nc to open telnet ports under Linux.

```console
#nc -l 10003 > destination 2>/dev/null&
time pid proto backlog ret port task
20:19:35 6538 131073 1 0 10003 nc 
20:19:35 6538 131073 1 0 10003 nc
^C
```

For more details, see docs/special_filtering.md

