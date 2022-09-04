use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

fn main() {
    build("src/bpf/dns_queries.bpf.c", "dns_queries.skel.rs");
}

fn build(src: &str, out_path: &str) {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push(out_path);
    SkeletonBuilder::new()
        .source(src)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={}", src);
}
