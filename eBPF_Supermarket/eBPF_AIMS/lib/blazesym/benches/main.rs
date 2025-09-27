#![allow(clippy::let_and_return, clippy::let_unit_value)]

macro_rules! bench_fn {
    ($group:expr, $bench_fn:ident) => {
        $group.bench_function(crate::bench_fn_name(stringify!($bench_fn)), |b| {
            b.iter($bench_fn)
        });
    };
}


mod inspect;
mod normalize;
mod symbolize;

use std::time::Duration;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;


const BENCH_NAME_WIDTH: usize = 42;


fn bench_fn_name(name: &str) -> String {
    format!("{name:<BENCH_NAME_WIDTH$}")
}


fn benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("main");
    group.warm_up_time(Duration::from_secs(1));
    group.confidence_level(0.98);
    group.significance_level(0.02);
    inspect::benchmark(&mut group);
    normalize::benchmark(&mut group);
    symbolize::benchmark(&mut group);
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
