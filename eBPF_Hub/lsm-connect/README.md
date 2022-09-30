# LSM demo

BPF LSM program (on socket_connect hook) that prevents any connection towards 1.1.1.1 to happen

## run

```console
docker run -it -v /path/to/lsm-connect:/src yunwei37/ebpm:latest
```

Run:

```console
sudo ./ecli run lsm-connect
```

## reference

https://github.com/leodido/demo-cloud-native-ebpf-day