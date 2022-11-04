mod config;
mod metrics;
mod utils;

use crate::{config::Config, metrics::METRICS};
use anyhow::{Context, Result};
use dns_parser::Packet;
use flume::Receiver;
use fxhash::FxBuildHasher;
use metrics::process_metrics_request;
use moka::{notification::RemovalCause, sync::Cache};
use std::{net::Ipv4Addr, sync::Arc, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
};
use tokio_fd::AsyncFd;
use tracing::{debug, info};
use tracing_subscriber::{
    filter::{EnvFilter},
    fmt,
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};
use utils::*;

lazy_static::lazy_static! {
    /// 全局配置文件，从当前目录读取 config.toml
    static ref CONFIG:Config = Config::from_file("config.toml").unwrap();

    /// 储存正在匹配的 DNS 请求的一些元数据
    /// key: (Addr,u16)  value: (String, Instant)  -> key: (地址，DNS id)  value: (域名，创建时间)
    static ref MATCHING: Cache<(Addr,u16), (String, Instant), FxBuildHasher> = Cache::builder()
        .max_capacity(CONFIG.matching.capacity)
        .time_to_live(CONFIG.matching.timeout)
        .eviction_listener(clean_timeout)
        .build_with_hasher(FxBuildHasher::default());

    /// 储存未匹配到的的的 DNS query 和 DNS request 的一些元数据
    /// key: (Addr,u16,Instant)  value: (String, Vec<Ipv4Addr>)  -> key: (地址，DNS id，创建时间)  value: (域名，ip 地址)
    static ref MATCHED: Cache<(Addr,u16,Instant), (String,Vec<Ipv4Addr>), FxBuildHasher> = Cache::builder()
        .time_to_live(CONFIG.matched.ttl)
        .max_capacity(CONFIG.matched.capacity)
        .build_with_hasher(FxBuildHasher::default());

    /// 储存未匹配到的 DNS query 的元数据
    /// key: (Arc<(Addr,u16)>,Instant) value: String -> key: (Arc<(地址，DNS id)>,创建时间)   value: 域名
    static ref UNMATCHED: Cache<(Arc<(Addr,u16)>,Instant),String, FxBuildHasher> = Cache::builder()
        .max_capacity(CONFIG.unmatched.capacity)
        .time_to_live(CONFIG.unmatched.ttl)
        .build_with_hasher(FxBuildHasher::default());

    /// 储存 缓存的 DNS 条目
    /// key: String   value: Vec<Ipv4Addr> -> key: 域名  value: ip 地址
    static ref CACHE: Cache<String, Vec<Ipv4Addr>, FxBuildHasher> = Cache::builder()
        .max_capacity(CONFIG.cache.capacity)
        .eviction_listener(manage_cache)
        .time_to_live(CONFIG.cache.ttl)
        .build_with_hasher(FxBuildHasher::default());

}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_default()
        .add_directive(format!("dns_cache={}", &CONFIG.global.log).parse()?)
        .add_directive("hyper=warn".parse()?);
    let filtered_layer = fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_filter(filter);
    tracing_subscriber::registry().with(filtered_layer).init();

    spawn(async {
        loop {
            tokio::time::sleep(CONFIG.global.report_interval).await;
            print_status()
        }
    });

    // 初始化 metrics handler
    spawn(process_metrics_request(&CONFIG.global.api_listen_at));

    let mut filter = AsyncFd::try_from(open_filter(&CONFIG.global.interface)?)?;

    let (rx, tx) = flume::bounded(CONFIG.global.worker);

    for _ in 0..(CONFIG.global.worker) {
        let tx = tx.clone();
        spawn(serve(tx));
    }

    loop {
        let mut buf = vec![0; BUF_SIZE];
        let size = skip_err!(filter.read(&mut buf).await);
        skip_err!(rx.send_async((buf, size)).await);
    }
}

async fn serve(tx: Receiver<(Vec<u8>, usize)>) {
    let mut sender = AsyncFd::try_from(open_socket(&CONFIG.global.interface).unwrap()).unwrap();

    while let Ok((buf, size)) = tx.recv_async().await {
        let (addr, dns) = skip_err!(parse_raw_packet(&buf[..size]));

        if dns.header.query {
            skip_err!(process_query(addr, dns, &mut sender).await);
        } else {
            process_reply(addr, dns);
        }
    }
}

async fn process_query(mut addr: Addr, dns: Packet<'_>, sender: &mut AsyncFd) -> Result<()> {
    let mut reply = vec![];
    let domain = extract_domain(&dns).with_context(|| "failed to extract domain from dns query")?;
    let id = dns.header.id;

    if is_need_inject() {
        if let Some(ip) = CACHE.get(&domain) {
            let instant = Instant::now();

            debug!("hit cache {domain} -> {ip:?}");

            let size = build_raw_dns_reply(dns.header.id, &domain, &ip, addr.swap(), &mut reply)?;
            sender.write_all(&reply[..size]).await?;

            MATCHED.insert((addr, id, instant), (domain.clone(), ip));
            METRICS.add_request_duration(instant.elapsed());
            METRICS.inc_matched_total();
            METRICS.inc_hit_cache();
            return Ok(());
        } else {
            debug!("miss cache {domain}");
            METRICS.inc_miss_cache();
        }
    }

    debug!("query: id {id}  {addr}  {domain}");
    MATCHING.insert((addr, id), (domain.clone(), Instant::now()));

    Ok(())
}

fn process_reply(addr: Addr, dns: Packet) -> Option<()> {
    let id = dns.header.id;
    let ips = extract_ip_from_dns_reply(&dns)?;

    let addr_id = &(addr.clone().swap().to_owned(), id);
    let (domain, instant) = MATCHING.get(addr_id)?;
    MATCHING.invalidate(addr_id);

    debug!(
        "reply: cost {:?}  id {id} {addr}  {domain} -> {ips:?}",
        instant.elapsed()
    );

    MATCHED.insert((addr, id, instant), (domain.clone(), ips.clone()));
    METRICS.inc_matched_total();
    METRICS.add_request_duration(instant.elapsed());

    CACHE.insert(domain, ips);

    Some(())
}

fn is_need_inject() -> bool {
    calc_loss() >= CONFIG.global.loss
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

fn clean_timeout(k: Arc<(Addr, u16)>, (domain, instant): (String, Instant), cause: RemovalCause) {
    if cause == RemovalCause::Expired {
        let (addr, id) = k.as_ref();
        debug!("timeout:  id {id}  {addr} {domain}");
        UNMATCHED.insert((k, instant), domain);
        METRICS.inc_unmatched_total();
    }
}

fn manage_cache(k: Arc<String>, v: Vec<Ipv4Addr>, cause: RemovalCause) {
    if cause == RemovalCause::Expired {
        debug!("delete cache {k} -> {v:?}")
    }
}

fn print_status() {
    let matching_len = MATCHING.entry_count();
    let unmatched_len = UNMATCHED.entry_count();
    let matched_len = MATCHED.entry_count();
    let cache_len = CACHE.entry_count();
    let loss = calc_loss() * 100.0;

    info!("loss {loss:.2}%  matching {matching_len}  matched {matched_len}  unmatched {unmatched_len}  cached {cache_len}");
}
