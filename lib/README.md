# common scripts for lmp

## build hub

makefile for build and test projects in eBPF_Hub

install deps(Ubuntu):

```bash
sudo make -C lib/build_hub install-deps
```

build all eBPF_Hub projects:

```sh
make -C lib/build_hub clone_and_install_deps
make -C lib/build_hub test
```
