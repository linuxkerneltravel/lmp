# projects

This folder contains projects for eBPF_hub.

## index

- [bindsnoop](bindsnoop) Trace bind syscalls.
- [bootstrap](bootstrap) an example of a simple (but realistic) BPF application
- [fentry-link](fentry-link) an example that uses fentry and fexit BPF programs for tracing
- [kprobe-link](kprobe-link) an example of dealing with kernel-space entry and exit (return) probes
- [mdflush](mdflush) Trace md flush events.
- [lsm-connect](lsm-connect) BPF LSM program (on socket_connect hook) that prevents any connection towards 1.1.1.1 to happen
- [minimal](minimal) a minimal example of a BPF application
- [mountsnoop](mountsnoop) Trace mount syscalls.
- [opensnoop](opensnoop) traces the open() syscall system-wide
- [sigsnoop](sigsnoop) Trace signal syscalls.
- [template](template) a template for new eunomia-bpf eBPF programs
- [tcpconnlat](tcpconnlat) Trace TCP connects and show connection latency.
- [statsnoop](statsnoop) Trace stat syscalls.

> FIXME: auto generated index

## Pre-requisites for use eBPF_hub

Re-compiling your Kernel with CONFIG_DEBUG_INFO_BTF=y
-----------------------------------------------------
libbpf probes to see if your sys fs exports the file `/sys/kernel/btf/vmlinux` (from Kernel 5.5+) or if you have the ELF version in your system [`code`](https://github.com/libbpf/libbpf/blob/master/src/btf.c)
Please note the ELF file could exist without the BTF info in it. Your Kconfig should contain the options below

1. Compile options
```code
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO=y
```
2. Also, make sure that you have pahole 1.13 (or preferably 1.16+) during the
kernel build (it comes from dwarves package). Without it, BTF won't be
generated, and on older kernels you'd get only warning, but still would
build kernel successfully

Running in kernels without CONFIG_DEBUG_INFO_BTF=y
--------------------------------------------------

It's possible to run some tools in kernels that don't expose
`/sys/kernel/btf/vmlinux`. For those cases,
[BTFGen](https://lore.kernel.org/bpf/20220215225856.671072-1-mauricio@kinvolk.io)
and [BTFHub](https://github.com/aquasecurity/btfhub) can be used to
generate small BTF files for the most popular Linux distributions that
are shipped with the tools in order to provide the needed information to
perform the CO-RE relocations when loading the eBPF programs.

If you haven't cloned the
[btfhub-archive](https://github.com/aquasecurity/btfhub) repository, you
can run make and it'll clone it for you into the `$HOME/.local/share`
directory:

```bash
make ENABLE_MIN_CORE_BTFS=1 -j$(nproc)
```

If you have a local copy of such repository, you can pass it's location
to avoid cloning it again:

```bash
make ENABLE_MIN_CORE_BTFS=1 BTF_HUB_ARCHIVE=<path_to_btfhub-archive> -j$(nproc)
```

## add new project

The project can be a dir or a git submodule, with at lease the following files:

- a `README,md`
- a `config.json`

If you use eunomia-bpf, the project will be build automaticly. 

Tools are expected to follow a simple naming convention:

  - <tool>.bpf.c contains BPF C code, which gets compiled into `package.json`
  - <tool>.bpf.h can optionally contain types exported to userspace through pref event or ring buffer
  - <tool>.h can optionally contain any types and constants, shared by both BPF and userspace sides of a tool.

You can check the [template](template) project for more details.

## reference

Most codes come from:

- libbpf-tools: https://github.com/iovisor/bcc/tree/master/libbpf-tools
- libbpf-bootstrap: https://github.com/libbpf/libbpf-bootstrap/tree/master/examples/c
- eunomia-bpf: https://github.com/eunomia-bpf
- documentations: https://eunomia-bpf.github.io/