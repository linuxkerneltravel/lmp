use anyhow::Result;
use dns_parser::Packet;
use flume::Receiver;
use std::{net::Ipv4Addr, str::FromStr, sync::Arc, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
};
use tokio_fd::AsyncFd;
use tracing::{debug, info, metadata::LevelFilter, trace};
mod utils;
use crate::config::Config;
use utils::*;
mod config;
use fxhash::FxBuildHasher;
use moka::{notification::RemovalCause, sync::Cache};

lazy_static::lazy_static! {
    static ref CONFIG:Config = Config::from_file("config.toml").unwrap();
    static ref MATCHING: Cache<(Addr,u16), (String, Instant), FxBuildHasher> = Cache::builder()
        .max_capacity(CONFIG.matching.capacity)
        .time_to_live(CONFIG.matching.timeout)
        .eviction_listener(clean_timeout)
        .build_with_hasher(FxBuildHasher::default());
    static ref MATCHED: Cache<(Addr,u16,Instant), (String,Vec<Ipv4Addr>), FxBuildHasher> = Cache::builder()
        .time_to_live(CONFIG.matched.ttl)
        .max_capacity(CONFIG.matched.capacity)
        .build_with_hasher(FxBuildHasher::default());
    static ref UNMATCHED: Cache<(Arc<(Addr,u16)>,Instant),String, FxBuildHasher> = Cache::builder()
        .max_capacity(CONFIG.unmatched.capacity)
        .time_to_live(CONFIG.unmatched.ttl)
        .build_with_hasher(FxBuildHasher::default());
    static ref CACHE: Cache<String, Vec<Ipv4Addr>, FxBuildHasher> = Cache::builder()
        .max_capacity(CONFIG.cache.capacity)
        .eviction_listener(manage_cache)
        .time_to_live(CONFIG.cache.ttl)
        .build_with_hasher(FxBuildHasher::default());

}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_file(true)
        .with_line_number(true)
        .with_max_level(LevelFilter::from_str(&CONFIG.global.log).unwrap())
        .init();

    spawn(async {
        loop {
            tokio::time::sleep(CONFIG.global.report_interval).await;
            print_status()
        }
    });

    CACHE.insert(
        "test.com".to_string(),
        vec!["114.114.114.114".parse().unwrap()],
    );

    let mut filter = AsyncFd::try_from(open_filter(&CONFIG.global.interface)?)?;

    let (rx, tx) = flume::bounded(CONFIG.global.worker);

    for _ in 0..(CONFIG.global.worker) {
        let tx = tx.clone();
        spawn(serve(tx));
    }

    loop {
        let mut buf = vec![0; BUF_SIZE];
        skip_err!(filter.read(&mut buf).await);
        skip_err!(rx.send_async(buf).await);
    }
}

async fn serve(tx: Receiver<Vec<u8>>) {
    let mut sender = AsyncFd::try_from(open_socket(&CONFIG.global.interface).unwrap()).unwrap();
    let reply = &mut [0; BUF_SIZE];

    while let Ok(buf) = tx.recv_async().await {
        let (mut addr, dns) = skip_err!(parse_raw_packet(&buf));

        if dns.header.query {
            if let Some(size) = process_query(addr, dns, reply) {
                if size != 0 {
                    sender.write(&reply[..size]).await.unwrap();
                }
            }
        } else {
            addr.swap();
            process_reply(addr, dns);
        }
    }
}

fn process_query(mut addr: Addr, dns: Packet<'_>, reply: &mut [u8]) -> Option<usize> {
    let domain = extract_domain(&dns)?;
    let id = dns.header.id;

    if is_need_inject() {
        if let Some(ip) = CACHE.get(&domain) {
            debug!("hit cache {domain} -> {ip:?}");
            let size = build_raw_dns_reply(dns.header.id, &domain, &ip, addr.swap(), reply)?;
            MATCHED.insert((addr,id,Instant::now()), (domain, ip));
            return Some(size);
        }
    }

    debug!("query: id {id}  {addr}  {domain}");
    MATCHING.insert((addr,id), (domain.clone(), Instant::now()));

    Some(0)
}

fn process_reply(addr: Addr, dns: Packet) -> Option<()> {
    let id = dns.header.id;
    let addr_id = &(addr.clone(),id);
    let (domain, instant) = MATCHING.get(addr_id)?;
    MATCHING.invalidate(addr_id);
    let ip = extract_ip_from_dns_reply(&dns)?;

    debug!(
        "reply: cost {:?}  id {id} {addr}  {domain} -> {ip:?}",
        instant.elapsed()
    );
    MATCHED.insert((addr,id, instant), (domain.clone(), ip.clone()));
    CACHE.insert(domain, ip);

    Some(())
}

fn is_need_inject() -> bool {
    if calc_loss() >= CONFIG.global.loss {
        return true;
    }

    false
}

fn calc_loss() -> f64 {
    let unmatched = UNMATCHED.entry_count();
    let matched = MATCHED.entry_count();

    if unmatched != 0 {
        let loss = unmatched as f64 / (matched as f64 + unmatched as f64);
        return loss;
    }

    0.0
}

fn clean_timeout(k: Arc<(Addr,u16)>, (domain, instant): (String, Instant), cause: RemovalCause) {
    match cause {
        RemovalCause::Expired => {
            let (addr,id) = k.as_ref();
            debug!("timeout:  id {id}  {addr} {domain}");
            UNMATCHED.insert((k, instant), domain);
        }
        _ => {}
    }
}

fn manage_cache(k: Arc<String>, v: Vec<Ipv4Addr>, cause: RemovalCause) {
    match cause {
        RemovalCause::Expired => debug!("delete cache {k} -> {v:?}"),
        _ => {}
    }
}

fn print_status() {
    let matching: Vec<_> = MATCHING.into_iter().collect();
    let unmatched: Vec<_> = UNMATCHED.into_iter().collect();
    let matched: Vec<_> = MATCHED.into_iter().collect();
    let cache: Vec<_> = CACHE.into_iter().collect();

    let matching_len = MATCHING.entry_count();
    let unmatched_len = UNMATCHED.entry_count();
    let matched_len = MATCHED.entry_count();
    let cache_len = CACHE.entry_count();
    let loss = calc_loss() * 100.0;

    trace!("matching  {:?}", matching);
    trace!("matched   {:?}", matched);
    trace!("unmatched {:?}", unmatched);
    trace!("cached    {:?}\n", cache);

    info!("loss {loss:.2}%  matching {matching_len}  matched {matched_len}  unmatched {unmatched_len}  cached {cache_len}");
}
