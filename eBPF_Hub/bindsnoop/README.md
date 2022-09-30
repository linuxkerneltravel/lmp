# sigsnoop

Trace bind syscalls.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/bindsnoop.bpf.c

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v /path/to/bindsnoop:/src yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run bindsnoop
```
