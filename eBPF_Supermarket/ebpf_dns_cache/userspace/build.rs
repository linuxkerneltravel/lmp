use cargo_bpf_lib::build;
use std::env;
use std::path::PathBuf;

fn main() {
    let cargo = PathBuf::from(env::var("CARGO").unwrap());
    let package = PathBuf::from("../probe");
    let target_dir = PathBuf::from("../target");

    build(&cargo, &package, &target_dir, vec!["dns_queries".into()]).unwrap();
    println!("cargo:rerun-if-changed=../probe");
}
