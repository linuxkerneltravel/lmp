use bollard::Docker;
use dashmap::DashMap;
use dns_parser::{RData, ResponseCode};
use packet_builder::payload::PayloadData;
use packet_builder::*;
use pnet::datalink::MacAddr;
use redbpf::load::Loader;
use static_init::dynamic;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::mem::{self};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Instant};
use tokio::{io, spawn};
use tokio_fd::AsyncFd;
use tracing::{error, info, trace, Level};
use tracing_subscriber::FmtSubscriber;

type Id = u16;

const _THRESHOLD: f64 = 0.2;
const WAIT_TIME: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
struct Addr {
    saddr: SocketAddr,
    daddr: SocketAddr,
    smac: MacAddr,
    dmac: MacAddr,
}

impl Hash for Addr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.saddr > self.daddr {
            self.saddr.hash(state);
            self.daddr.hash(state);
        } else {
            self.daddr.hash(state);
            self.saddr.hash(state);
        }

        if self.smac > self.dmac {
            self.smac.hash(state);
            self.dmac.hash(state);
        } else {
            self.dmac.hash(state);
            self.smac.hash(state);
        }
    }
}

lazy_static::lazy_static! {
    static ref MATCHING_MAP: DashMap<(Id, u64), (Addr,Vec<String>)> = DashMap::new();
    static ref CACHED_MAP: DashMap<String, Vec<Ipv4Addr>> = DashMap::new();
}

#[dynamic]
static mut UNMATCHED: Vec<(Addr, Vec<String>, Instant)> = Vec::new();

#[dynamic]
static mut TOTAL: u64 = 0;

macro_rules! skip_fail {
    ($res:expr) => {
        match $res {
            Some(val) => val,
            None => {
                info!("skipping fail");
                continue;
            }
        }
    };
}

fn build_dns_reply(id: Id, domain: &str, ips: &[Ipv4Addr]) -> Option<Vec<u8>> {
    use simple_dns::rdata::*;
    use simple_dns::*;
    let question = Question::new(Name::new_unchecked(domain), QTYPE::A, QCLASS::IN, false);

    let mut header = PacketHeader::new_reply(id, OPCODE::StandardQuery);
    header.authoritative_answer = true;
    header.recursion_desired = true;
    header.recursion_available = true;

    let mut packet = PacketBuf::new(header, true);

    packet.add_question(&question).ok()?;

    for ip in ips {
        let answer = ResourceRecord::new(
            Name::new_unchecked(domain),
            CLASS::IN,
            10,
            RData::A(A {
                address: (*ip).into(),
            }),
        );
        skip_fail!(packet.add_answer(&answer).ok())
    }

    Some(packet.to_vec())
}

#[tokio::main]
async fn main() {
    init();

    let mut loaded = Loader::load(probe_code())
        .map_err(|err| format!("{:?}", err))
        .unwrap();
    let fd = loaded
        .socket_filter_mut("dns_queries")
        .unwrap()
        .attach_socket_filter("docker0")
        .unwrap();
    let filter = AsyncFd::try_from(fd).unwrap();
    let (mut rx, mut tx) = io::split(filter);

    CACHED_MAP.insert(
        "7777.com".to_string(),
        vec!["114.114.114.114".parse().unwrap()],
    );
    /*
        spawn(async move {
            loop {
                if (calc_loss() > THRESHOLD) & (MATCHING_MAP.len() > 0) {
                    let mut keys = vec![];

                    for r in MATCHING_MAP.iter() {
                        let mut addr = r.0;
                        let domain = &r.1[0];
                        let id = r.key().0;

                        mem::swap(&mut addr.saddr, &mut addr.daddr);
                        mem::swap(&mut addr.smac, &mut addr.dmac);

                        if let Some(a) = CACHED_MAP.get(domain) {
                            let ips = a.value();

                            info!("hit cache!   {addr:?}  {id} {domain} -> {ips:?}");
                            let payload = skip_fail!(build_dns_reply(id, domain, ips));
                            send_raw_udp_packet(&mut tx, &addr, &payload).await;

                            keys.push(*r.key());
                        }
                    }

                    let count = keys.iter().map(|key| MATCHING_MAP.remove(key)).count();
                    if count > 0 {
                        info!("release {count} matching query");
                    }
                }

                sleep(Duration::from_secs_f32(0.01)).await;
            }
        });
    */
    let mut buf = [0u8; 2048];

    while let Ok(n) = rx.read(&mut buf).await {
        let (addr, buf) = skip_fail!(parse_raw_packet(&buf[..n]));

        let packet = skip_fail!(dns_parser::Packet::parse(buf).ok());
        let id = packet.header.id;
        let addr_hash = hash(&addr);
        trace!("{id} {packet:?}");
        if let Some((_, (_addr, domains))) = MATCHING_MAP.remove(&(id, addr_hash)) {
            // dns query reply

            if packet.header.response_code == ResponseCode::Refused {
                UNMATCHED.write().push((addr, domains, Instant::now()));
                log_status();
                continue;
            }

            let ips: Vec<Ipv4Addr> = packet
                .answers
                .iter()
                .filter_map(|r| {
                    if let RData::A(a) = &r.data {
                        Some(a.0)
                    } else {
                        None
                    }
                })
                .collect();

            if ips.is_empty() {
                continue;
            }

            info!(
                "{:?} {id} {} <--> {}\t{} -> {:?}",
                get_container_nane_by_ip(addr.daddr.ip()).await,
                addr.daddr,
                addr.saddr,
                domains[0],
                ips
            );

            log_status();

            for domain in domains {
                CACHED_MAP.insert(domain, ips.clone());
            }
        } else {
            // dns query request
            if !packet.header.query {
                continue;
            }

            let domains: Vec<String> = packet
                .questions
                .iter()
                .map(|q| q.qname.to_string())
                .collect();

            // test whether cache and DNS packet injection work
            let domain = &domains[0];
            if let Some(a) = CACHED_MAP.get(domain) {
                let ips = a.value();
                info!("hit chahe and inject {id} {domain} -> {ips:?}");
                let payload = skip_fail!(build_dns_reply(id, domain, ips));

                let mut addr = addr.clone();

                mem::swap(&mut addr.saddr, &mut addr.daddr);
                //mem::swap(&mut addr.smac, &mut addr.dmac);

                send_raw_udp_packet(&mut tx, &addr, &payload).await;
            }

            MATCHING_MAP.insert((id, addr_hash), (addr, domains));

            {
                *TOTAL.write() += 1;
            }

            // deal with timeout request
            spawn(async move {
                sleep(WAIT_TIME).await;

                /*
                // lock matching map when loss is bigger than threshold
                if calc_loss() > THRESHOLD {
                    sleep(WAIT_TIME).await;
                }
                */

                if let Some((_, (_, domains))) = MATCHING_MAP.remove(&(id, addr_hash)) {
                    info!("unmatched {:?}", (addr, &domains));
                    UNMATCHED.write().push((addr, domains, Instant::now()));
                }
            });
        }
    }
}

fn log_status() {
    let matching = MATCHING_MAP.len();
    let cached = CACHED_MAP.len();
    let unmatched = UNMATCHED.read().len();
    let total = *TOTAL.read();
    let loss = ((unmatched as f64) / (total as f64)) * 100f64;
    info!(
        "total: {total}   matching: {matching}   cached: {cached}   unmached: {unmatched}   loss: {loss:.2}%"
        );
}

fn calc_loss() -> f64 {
    let unmatched = UNMATCHED.read().len();
    let total = *TOTAL.read();

    (unmatched as f64) / (total as f64)
}

async fn get_container_nane_by_ip(addr: IpAddr) -> Option<(String, Vec<String>)> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let v = docker.list_containers::<&str>(None).await.unwrap();

    let mut result = HashMap::new();

    v.into_iter()
        .filter_map(|summary| {
            let (id, names) = (summary.id?, summary.names?);

            let names: Vec<_> = names
                .iter()
                .map(|x| x.trim_start_matches('/').to_string())
                .collect();

            let networks = summary.network_settings?.networks?;
            let ips: Vec<_> = networks
                .into_values()
                .filter_map(|settings| {
                    let ip = settings.ip_address?;
                    IpAddr::from_str(&ip).ok()
                })
                .collect();

            for ip in ips {
                result.insert(ip, (id.clone(), names.clone()));
            }

            Some(())
        })
        .count();

    result
        .get(&addr)
        .and_then(|(id, names)| Some((id.clone(), names.clone())))
}

fn parse_raw_packet(buf: &[u8]) -> Option<(Addr, &[u8])> {
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::{Packet, PacketSize};

    let eth_packet = EthernetPacket::new(buf)?;
    let ipv4_packet = Ipv4Packet::new(eth_packet.payload())?;
    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;

    let saddr = ipv4_packet.get_source();
    let daddr = ipv4_packet.get_destination();
    let sport = udp_packet.get_source();
    let dport = udp_packet.get_destination();

    let saddr = SocketAddr::from(SocketAddrV4::new(saddr, sport));
    let daddr = SocketAddr::from(SocketAddrV4::new(daddr, dport));

    let smac = eth_packet.get_source();
    let dmac = eth_packet.get_destination();

    let offset = eth_packet.packet_size()
        + ipv4_packet.get_header_length() as usize * 4
        + udp_packet.packet_size();

    let addr = Addr {
        saddr,
        daddr,
        smac,
        dmac,
    };

    Some((addr, &buf[offset..]))
}

async fn send_raw_udp_packet<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    addr: &Addr,
    payload: &[u8],
) -> Option<()> {
    use pnet::packet::Packet;
    let mut pkt_buf = [0u8; 1024];

    let pkt = match (addr.saddr, addr.daddr) {
        (SocketAddr::V4(saddr), SocketAddr::V4(daddr)) => packet_builder!(
             pkt_buf,
             ether({set_destination => addr.smac, set_source => addr.dmac }) /
             ipv4({set_source =>  *saddr.ip() , set_destination => *daddr.ip() }) /
             udp({set_source => saddr.port(), set_destination =>daddr.port() }) /
             payload(payload)
        ),
        (SocketAddr::V6(_saddr), SocketAddr::V6(_daddr)) => panic!("we don't support IPv6 yet"),
        _ => unreachable!(),
    };

    w.write_all(pkt.packet()).await.ok()
}

fn init() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        std::process::exit(1);
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!("../../target/bpf/programs/dns_queries/dns_queries.elf")
}

fn hash<T>(obj: &T) -> u64
where
    T: Hash,
{
    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish()
}
