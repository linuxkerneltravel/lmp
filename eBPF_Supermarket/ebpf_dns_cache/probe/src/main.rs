#![no_std]
#![no_main]

use core::mem;

use memoffset::offset_of;
use redbpf_probes::bindings::*;
use redbpf_probes::socket_filter::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[socket_filter]
pub fn dns_queries(skb: SkBuff) -> SkBuffResult {
    let eth_len = mem::size_of::<ethhdr>();
    let eth_proto = skb.load::<__be16>(offset_of!(ethhdr, h_proto))? as u32;

    if eth_proto == ETH_P_IP {
        let mut ip_hdr = unsafe { mem::zeroed::<iphdr>() };
        ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_len)?]);

        if ip_hdr.version() == 4 {
            let ip_len = ip_hdr.ihl() as usize * 4;
            let protocol = skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u32;

            if protocol != IPPROTO_UDP {
                return Ok(SkBuffAction::Ignore);
            } else {
                let proto_len = mem::size_of::<udphdr>();
                let dns_qcount: u16 = skb.load(eth_len + ip_len + proto_len + 4)?;
                if dns_qcount == 1 {
                    return Ok(SkBuffAction::SendToUserspace);
                }
            }
        } else {
            return Ok(SkBuffAction::Ignore);
        };

        return Ok(SkBuffAction::Ignore);
    }
    Ok(SkBuffAction::Ignore)
}
