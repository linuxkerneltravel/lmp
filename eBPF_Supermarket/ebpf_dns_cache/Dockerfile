FROM frolvlad/alpine-glibc:latest AS builder

RUN apk add --no-cache clang elfutils-dev libelf zlib pkgconfig cargo rustfmt linux-headers make

WORKDIR /workspace
COPY . ebpf-dns-cache
WORKDIR /workspace/ebpf-dns-cache
RUN cargo build --release

FROM frolvlad/alpine-glibc:latest 
WORKDIR /root/
COPY --from=builder /workspace/ebpf-dns-cache/target/release/dns-cache ./
RUN apk add --no-cache libelf zlib
CMD ["./dns-cache"] 