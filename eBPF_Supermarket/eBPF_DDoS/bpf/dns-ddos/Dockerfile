FROM docker.m.daocloud.io/ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update &&\
    apt-get install -y git cmake make gcc python3 libncurses-dev gawk flex bison openssl \
    libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
    
RUN apt-get install -y clang iproute2 bpfcc-tools

RUN git clone -b v5.4 https://gitee.com/mirrors/linux_old1 --depth 1 && \
    cd linux_old1/tools/bpf/bpftool && make && make install
