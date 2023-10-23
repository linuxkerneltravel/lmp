FROM docker.m.daocloud.io/golang:1.18.6 as compiler
WORKDIR /app

COPY . .

RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.cn,direct && go mod download

RUN go build -ldflags "-s -w" -o lmpddos ./main.go

FROM docker.m.daocloud.io/ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update &&\
    apt-get install -y git cmake make gcc python3 libncurses-dev gawk flex bison openssl \
    libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
    
RUN apt-get install -y clang iproute2 bpfcc-tools

RUN git clone -b v5.4 https://gitee.com/mirrors/linux_old1 --depth 1 && \
    cd linux_old1/tools/bpf/bpftool && make && make install

# FROM bpf-builder:latest

COPY --from=compiler /app/lmpddos lmpddos
COPY bpf bpf

# test dns
# docker run --privileged --rm -it --network=container:dwq-coredns --name lmpddos -v /lib/modules:/lib/modules -v /usr/src:/usr/src -v /sys/kernel/debug:/sys/kernel/debug:rw -v /sys/fs/bpf:/sys/fs/bpf lmpddos:1.0 bash
