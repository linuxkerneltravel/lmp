FROM ghcr.io/foniod/redbpf-build:latest-x86_64-archlinux AS builder

RUN pacman -Sy && pacman -S --noconfirm git

WORKDIR /workspace

COPY . ebpf-dns-cache

WORKDIR /workspace/ebpf-dns-cache

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest  

WORKDIR /root/
COPY --from=builder /workspace/ebpf-dns-cache/target/x86_64-unknown-linux-musl/release/bpf-dns ./
CMD ["./bpf-dns"]  
