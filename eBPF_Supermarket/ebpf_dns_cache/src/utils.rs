use std::fmt::Display;
use std::io;
use std::net::Ipv4Addr;

use anyhow::bail;
use anyhow::Result;

mod dns_queries {
    include!(concat!(env!("OUT_DIR"), "/dns_queries.skel.rs"));
}

use dns_parser::Packet;
use dns_parser::QueryType;
use dns_queries::*;

pub const BUF_SIZE: usize = 42 + 512; // 42 + 512 = (ethernet_header + ip_header + udp_header) + dns_max_length

macro_rules! skip_err {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                tracing::trace!("skipping err: {e:?}");
                continue;
            }
        }
    };
}
pub(crate) use skip_err;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Addr {
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
    pub saddr: Ipv4Addr,
    pub daddr: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}:{} <-> {:?}:{}",
            self.saddr, self.sport, self.daddr, self.dport
        )
    }
}

impl Addr {
    pub fn swap(&mut self) -> &mut Self {
        std::mem::swap(&mut self.saddr, &mut self.daddr);
        std::mem::swap(&mut self.smac, &mut self.dmac);
        std::mem::swap(&mut self.sport, &mut self.dport);
        self
    }
}

pub fn extract_domain(packet: &dns_parser::Packet) -> Option<String> {
    packet
        .questions
        .iter()
        .filter_map(|q| {
            if q.qtype == QueryType::A {
                Some(q.qname.to_string())
            } else {
                None
            }
        })
        .next()
}

pub fn parse_raw_packet(buf: &[u8]) -> Result<(Addr, Packet)> {
    use etherparse::InternetSlice::*;
    use etherparse::LinkSlice::*;
    use etherparse::TransportSlice::*;
    use etherparse::*;

    let packet = SlicedPacket::from_ethernet(buf)?;

    let (smac, dmac) = match packet.link {
        Some(Ethernet2(value)) => (value.source(), value.destination()),
        _ => {
            bail!("failed to parse mac addr")
        }
    };

    let (saddr, daddr) = match packet.ip {
        Some(Ipv4(value, _)) => (value.source_addr(), value.destination_addr()),
        _ => {
            bail!("we don't support ipv6")
        }
    };

    let (sport, dport) = match packet.transport {
        Some(Udp(value)) => (value.source_port(), value.destination_port()),
        _ => {
            bail!("failed to parse udp sport and dport")
        }
    };

    let addr = Addr {
        smac,
        dmac,
        saddr,
        daddr,
        sport,
        dport,
    };

    let packet = dns_parser::Packet::parse(packet.payload)?;

    Ok((addr, packet))
}

pub fn open_socket(interface: &Option<String>) -> Result<i32> {
    unsafe {
        let sock = libc::socket(
            libc::PF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be().into(),
        );

        if sock == -1 {
            bail!("Failed to create socket")
        }

        let interface = if let Some(interface) = interface {
            interface
        } else {
            return Ok(sock);
        };

        let mut sll = std::mem::zeroed::<libc::sockaddr_ll>();
        sll.sll_family = libc::AF_PACKET as u16;
        let ciface = std::ffi::CString::new(&**interface)?;
        sll.sll_ifindex = libc::if_nametoindex(ciface.as_ptr()) as i32;
        if sll.sll_ifindex == 0 {
            libc::close(sock);
            bail!("failed to find interface");
        }

        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be() as u16;
        if libc::bind(
            sock,
            &sll as *const _ as *const _,
            std::mem::size_of_val(&sll) as u32,
        ) < 0
        {
            libc::close(sock);
            bail!("failed to bind interface");
        }

        Ok(sock)
    }
}

pub fn open_filter(interface: &Option<String>) -> Result<i32> {
    let builder = DnsQueriesSkelBuilder::default();

    let skel = builder
        .open()
        .expect("Failed to open BPF program")
        .load()
        .expect("Failed to load BPF program");

    let sock = open_socket(interface)?;

    unsafe {
        let prog_fd = skel.progs().dns_queries().fd();
        let value = &prog_fd as *const i32;
        let option_len = std::mem::size_of_val(&prog_fd) as libc::socklen_t;

        let sockopt = libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            value as *const libc::c_void,
            option_len,
        );

        if sockopt != 0 {
            bail!("Failed to set socket option");
        }

        Ok(sock)
    }
}

pub fn extract_ip_from_dns_reply(packet: &Packet) -> Option<Vec<Ipv4Addr>> {
    let ips: Vec<Ipv4Addr> = packet
        .answers
        .iter()
        .filter_map(|r| {
            if let dns_parser::rdata::RData::A(a) = &r.data {
                Some(a.0)
            } else {
                None
            }
        })
        .collect();

    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

pub fn build_raw_dns_reply<T: io::Write + Sized>(
    id: u16,
    domain: &str,
    ips: &[Ipv4Addr],
    to: &Addr,
    writer: &mut T,
) -> Result<usize> {
    use etherparse::PacketBuilder;

    let builder = PacketBuilder::ethernet2(to.smac, to.dmac)
        .ipv4(to.saddr.octets(), to.daddr.octets(), 64)
        .udp(to.sport, to.dport);

    let payload = build_dns_reply(id, domain, ips)?;
    let size = builder.size(payload.len());
    builder.write(writer, &payload)?;

    Ok(size)
}

fn build_dns_reply(id: u16, domain: &str, ips: &[Ipv4Addr]) -> Result<Vec<u8>> {
    use simple_dns::rdata::*;
    use simple_dns::*;
    let question = Question::new(Name::new_unchecked(domain), QTYPE::A, QCLASS::IN, false);

    let mut header = PacketHeader::new_reply(id, OPCODE::StandardQuery);
    header.authoritative_answer = true;
    header.recursion_desired = true;
    header.recursion_available = true;

    let mut packet = PacketBuf::new(header, false);

    packet.add_question(&question)?;

    for ip in ips {
        let answer = ResourceRecord::new(
            Name::new_unchecked(domain),
            CLASS::IN,
            10,
            RData::A(A {
                address: (*ip).into(),
            }),
        );
        packet.add_answer(&answer).ok();
    }

    Ok(packet.to_vec())
}
