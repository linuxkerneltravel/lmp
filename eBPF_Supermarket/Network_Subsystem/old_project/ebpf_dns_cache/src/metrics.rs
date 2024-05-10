use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use serde::Serialize;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::{calc_loss, CACHE, MATCHED, MATCHING, UNMATCHED};

lazy_static::lazy_static! {
    pub static ref METRICS:Arc<Metrics> = Arc::new(Metrics {
        query: Counter::default(),
        reply: Counter::default(),
        cache_size: Gauge::default(),
        matched_total: Counter::default(),
        unmatched_total: Counter::default(),
        request_duration: Histogram::new(exponential_buckets(0.25, 2.0, 16)),
        loss: Gauge::default(),
        hit_cache: Counter::default(),
        miss_cache: Counter::default()
    });
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
struct Zone {
    domain: String,
}

pub struct Metrics {
    loss: Gauge<f64, AtomicU64>,
    cache_size: Gauge<u64>,
    unmatched_total: Counter,
    matched_total: Counter,
    request_duration: Histogram,
    query: Counter,
    reply: Counter,
    hit_cache: Counter,
    miss_cache: Counter,
}

impl Metrics {
    pub fn inc_unmatched_total(&self) {
        self.unmatched_total.inc();
    }

    pub fn inc_matched_total(&self) {
        self.matched_total.inc();
    }

    pub fn inc_miss_cache(&self) {
        self.miss_cache.inc();
    }

    pub fn inc_hit_cache(&self) {
        self.hit_cache.inc();
    }

    pub fn add_request_duration(&self, duration: std::time::Duration) {
        self.request_duration.observe(duration.as_millis() as f64);
    }

    pub fn update_loss(&self) {
        let loss = calc_loss();
        self.loss.set(loss);
    }

    pub fn update_cache_size(&self) {
        let cache_size = CACHE.entry_count();
        self.cache_size.set(cache_size);
    }
}

pub struct AppState {
    pub registry: Registry,
}

pub async fn process_metrics_request(listen_at: &str) {
    let mut state = AppState {
        registry: Registry::default(),
    };

    state.registry.register(
        "dnscache_loss",
        "Current DNS request loss ratio",
        Box::new(METRICS.loss.clone()),
    );
    state.registry.register(
        "dnscache_dns_queries",
        "DNS query information",
        Box::new(METRICS.query.clone()),
    );
    state.registry.register(
        "dnscache_dns_replies",
        "DNS reply information",
        Box::new(METRICS.reply.clone()),
    );

    state.registry.register(
        "dnscache_unmatched_dns_queries",
        "count of unmatched DNS query",
        Box::new(METRICS.unmatched_total.clone()),
    );

    state.registry.register(
        "dnscache_matched_dns_queries",
        "count of matched DNS query and reply",
        Box::new(METRICS.matched_total.clone()),
    );

    state.registry.register(
        "dnscache_cache_size",
        "entry count of DNS cache",
        Box::new(METRICS.cache_size.clone()),
    );

    state.registry.register(
        "dnscache_dns_request_duration_milliseconds",
        "duration to process each query",
        Box::new(METRICS.request_duration.clone()),
    );

    state.registry.register(
        "dnscache_cache_hit",
        "count of hit cache",
        Box::new(METRICS.hit_cache.clone()),
    );

    state.registry.register(
        "dnscache_cache_miss",
        "count of miss cache",
        Box::new(METRICS.miss_cache.clone()),
    );

    let state = Arc::new(Mutex::new(state));

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/info/cache", get(cache_info_handler))
        .route("/info/unmatched", get(unmatched_info_handler))
        .route("/info/matched", get(matched_info_handler))
        .route("/info/matching", get(matching_info_handler))
        .layer(Extension(state));

    let addr = listen_at.parse().unwrap();
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn metrics_handler(state: Extension<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    METRICS.update_loss();
    METRICS.update_cache_size();
    let state = state.lock().unwrap();
    let mut buf = Vec::new();
    encode(&mut buf, &state.registry).unwrap();
    let body = std::str::from_utf8(buf.as_slice()).unwrap().to_string();
    body
}

async fn cache_info_handler() -> impl IntoResponse {
    #[derive(Debug, Serialize)]
    struct CacheRecord {
        domain: String,
        ip: Vec<String>,
    }

    let record: Vec<CacheRecord> = CACHE
        .iter()
        .map(|(domain, ips)| CacheRecord {
            domain: domain.to_string(),
            ip: ips.iter().map(|x| x.to_string()).collect(),
        })
        .collect();
    serde_json::to_string(&record).unwrap_or_default()
}

async fn unmatched_info_handler() -> impl IntoResponse {
    #[derive(Debug, Serialize)]
    struct UnmatchedRecord {
        domain: String,
        saddr: String,
        daddr: String,
        dns_id: u16,
    }

    let record: Vec<UnmatchedRecord> = UNMATCHED
        .into_iter()
        .map(|(arc, domain)| {
            let x = &arc.0;
            let addr = &x.0;
            let dns_id = &x.1;

            UnmatchedRecord {
                domain,
                saddr: format!("{}:{}", addr.saddr, addr.sport),
                daddr: format!("{}:{}", addr.daddr, addr.dport),
                dns_id: *dns_id,
            }
        })
        .collect();

    serde_json::to_string(&record).unwrap_or_default()
}

async fn matched_info_handler() -> impl IntoResponse {
    #[derive(Debug, Serialize)]
    struct MatchedRecord {
        domain: String,
        saddr: String,
        daddr: String,
        dns_id: u16,
        ip: Vec<String>,
    }

    let record: Vec<MatchedRecord> = MATCHED
        .into_iter()
        .map(|(arc, (domain, ip))| {
            let addr = &arc.0;
            let dns_id = &arc.1;

            MatchedRecord {
                domain,
                saddr: format!("{}:{}", addr.saddr, addr.sport),
                daddr: format!("{}:{}", addr.daddr, addr.dport),
                dns_id: *dns_id,
                ip: ip.iter().map(|ip| ip.to_string()).collect(),
            }
        })
        .collect();

    serde_json::to_string(&record).unwrap_or_default()
}

async fn matching_info_handler() -> impl IntoResponse {
    #[derive(Debug, Serialize)]
    struct MatchedRecord {
        domain: String,
        saddr: String,
        daddr: String,
        dns_id: u16,
    }

    let record: Vec<MatchedRecord> = MATCHING
        .into_iter()
        .map(|(arc, (domain, _))| {
            let addr = &arc.0;
            let dns_id = &arc.1;

            MatchedRecord {
                domain,
                saddr: format!("{}:{}", addr.saddr, addr.sport),
                daddr: format!("{}:{}", addr.daddr, addr.dport),
                dns_id: *dns_id,
            }
        })
        .collect();

    serde_json::to_string(&record).unwrap_or_default()
}
