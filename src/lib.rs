//! `lantern-network` — LanternOS's minimal network stack
//! ([RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)): Ethernet II, ARP, IPv4 and UDP, and nothing
//! else. It parses what the network sends and builds what the system sends, with no allocation and no syscalls, so the
//! confined `net` service is a thin loop around it and every check here is host-tested.
//!
//! Everything from the network is hostile. A frame is dropped, never half-handled, unless every length and checksum checks:
//! no IP options beyond what the header length covers, no fragments, no broadcast or multicast sources, nothing for another
//! address.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub type Mac = [u8; 6];
pub type Ip = [u8; 4];

pub const ETH_HEADER: usize = 14;
pub const IP_HEADER: usize = 20;
pub const UDP_HEADER: usize = 8;
pub const ARP_LEN: usize = 28;
/// The largest frame this stack builds or takes: Ethernet's 1500-byte payload and its header.
pub const MTU: usize = 1500;
pub const FRAME_MAX: usize = ETH_HEADER + MTU;
/// The most a UDP payload can be in one unfragmented datagram.
pub const UDP_MAX: usize = MTU - IP_HEADER - UDP_HEADER;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const PROTO_UDP: u8 = 17;
pub const BROADCAST: Mac = [0xff; 6];

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The Internet checksum (RFC 1071) of `parts`, as one stream.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match odd.take() {
                Some(hi) => sum += u16::from_be_bytes([hi, b]) as u32,
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u16::from_be_bytes([hi, 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(src: Ip, dst: Ip, udp: &[u8]) -> u16 {
    let len = (udp.len() as u16).to_be_bytes();
    let pseudo = [src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], 0, PROTO_UDP, len[0], len[1]];
    match checksum(&[&pseudo, udp]) {
        0 => 0xffff,
        c => c,
    }
}

/// A frame this host should act on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Incoming<'a> {
    /// An ARP request for this host's address: answer it.
    ArpRequest { mac: Mac, ip: Ip },
    /// An ARP reply: who has an address.
    ArpReply { mac: Mac, ip: Ip },
    /// A UDP datagram to this host.
    Udp { from: Ip, from_port: u16, to_port: u16, payload: &'a [u8] },
}

/// Parses `frame`, as received by a host at `mac` and `ip`. `None` for anything else, or anything malformed.
pub fn parse(frame: &[u8], mac: Mac, ip: Ip) -> Option<Incoming<'_>> {
    if frame.len() < ETH_HEADER || frame.len() > FRAME_MAX {
        return None;
    }
    let dst: Mac = frame[..6].try_into().ok()?;
    let src: Mac = frame[6..12].try_into().ok()?;
    if (dst != mac && dst != BROADCAST) || src[0] & 1 != 0 {
        return None;
    }
    let body = &frame[ETH_HEADER..];
    match u16_at(frame, 12) {
        ETHERTYPE_ARP => parse_arp(body, src, ip),
        ETHERTYPE_IPV4 if dst == mac => parse_ipv4(body, ip),
        _ => None,
    }
}

fn parse_arp(arp: &[u8], src: Mac, ip: Ip) -> Option<Incoming<'_>> {
    // Ethernet, IPv4, 6- and 4-byte addresses.
    if arp.len() < ARP_LEN || arp[..6] != [0, 1, 8, 0, 6, 4] {
        return None;
    }
    let sender_mac: Mac = arp[8..14].try_into().ok()?;
    let sender_ip: Ip = arp[14..18].try_into().ok()?;
    let target_ip: Ip = arp[24..28].try_into().ok()?;
    if sender_mac != src || sender_mac[0] & 1 != 0 || target_ip != ip {
        return None;
    }
    match u16_at(arp, 6) {
        1 => Some(Incoming::ArpRequest { mac: sender_mac, ip: sender_ip }),
        2 => Some(Incoming::ArpReply { mac: sender_mac, ip: sender_ip }),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8], ip: Ip) -> Option<Incoming<'_>> {
    if packet.len() < IP_HEADER || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let total = u16_at(packet, 2) as usize;
    if ihl < IP_HEADER || total < ihl || total > packet.len() || checksum(&[&packet[..ihl]]) != 0 {
        return None;
    }
    // No fragments: neither "more fragments" nor an offset.
    if u16_at(packet, 6) & 0x3fff != 0 || packet[9] != PROTO_UDP || packet[16..20] != ip {
        return None;
    }
    let from: Ip = packet[12..16].try_into().ok()?;
    if from == [255; 4] || from[0] >= 224 || from == [0; 4] {
        return None;
    }
    let udp = &packet[ihl..total];
    if udp.len() < UDP_HEADER || u16_at(udp, 4) as usize != udp.len() {
        return None;
    }
    let sum = u16_at(udp, 6);
    if sum != 0 {
        let mut copy = [0u8; MTU];
        copy[..udp.len()].copy_from_slice(udp);
        copy[6] = 0;
        copy[7] = 0;
        if udp_checksum(from, ip, &copy[..udp.len()]) != sum {
            return None;
        }
    }
    Some(Incoming::Udp { from, from_port: u16_at(udp, 0), to_port: u16_at(udp, 2), payload: &udp[UDP_HEADER..] })
}

/// Builds an ARP request from `(mac, ip)` for `target`, broadcast. Returns its length.
pub fn arp_request(mac: Mac, ip: Ip, target: Ip, out: &mut [u8]) -> usize {
    arp(1, mac, ip, BROADCAST, [0; 6], target, out)
}

/// Builds an ARP reply from `(mac, ip)` to `(to_mac, to_ip)`. Returns its length.
pub fn arp_reply(mac: Mac, ip: Ip, to_mac: Mac, to_ip: Ip, out: &mut [u8]) -> usize {
    arp(2, mac, ip, to_mac, to_mac, to_ip, out)
}

fn arp(op: u16, mac: Mac, ip: Ip, eth_dst: Mac, target_mac: Mac, target_ip: Ip, out: &mut [u8]) -> usize {
    out[..6].copy_from_slice(&eth_dst);
    out[6..12].copy_from_slice(&mac);
    out[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    let a = &mut out[ETH_HEADER..ETH_HEADER + ARP_LEN];
    a[..6].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
    a[6..8].copy_from_slice(&op.to_be_bytes());
    a[8..14].copy_from_slice(&mac);
    a[14..18].copy_from_slice(&ip);
    a[18..24].copy_from_slice(&target_mac);
    a[24..28].copy_from_slice(&target_ip);
    ETH_HEADER + ARP_LEN
}

/// The addresses a datagram goes between.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Route {
    pub mac: Mac,
    pub ip: Ip,
    pub port: u16,
    pub to_mac: Mac,
    pub to_ip: Ip,
    pub to_port: u16,
}

/// Builds a UDP datagram carrying `payload` along `route`. `None` if it's over [`UDP_MAX`] or `out` is too short.
pub fn udp(route: Route, id: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if payload.len() > UDP_MAX {
        return None;
    }
    let total = IP_HEADER + UDP_HEADER + payload.len();
    let frame = out.get_mut(..ETH_HEADER + total)?;
    frame[..6].copy_from_slice(&route.to_mac);
    frame[6..12].copy_from_slice(&route.mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    let (ip, udp) = frame[ETH_HEADER..].split_at_mut(IP_HEADER);
    ip.copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[12..16].copy_from_slice(&route.ip);
    ip[16..20].copy_from_slice(&route.to_ip);
    let sum = checksum(&[ip]);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    udp[..2].copy_from_slice(&route.port.to_be_bytes());
    udp[2..4].copy_from_slice(&route.to_port.to_be_bytes());
    udp[4..6].copy_from_slice(&((UDP_HEADER + payload.len()) as u16).to_be_bytes());
    udp[6..8].fill(0);
    udp[UDP_HEADER..].copy_from_slice(payload);
    let sum = udp_checksum(route.ip, route.to_ip, udp);
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    Some(ETH_HEADER + total)
}

/// The next hop for `to` from a host at `ip` on a /24 with gateway `gateway`.
pub fn next_hop(ip: Ip, gateway: Ip, to: Ip) -> Ip {
    if to[..3] == ip[..3] {
        to
    } else {
        gateway
    }
}

/// A few addresses this host has resolved.
#[derive(Default)]
pub struct ArpCache {
    entries: [Option<(Ip, Mac)>; 8],
    next: usize,
}

impl ArpCache {
    pub fn get(&self, ip: Ip) -> Option<Mac> {
        self.entries.iter().flatten().find(|(i, _)| *i == ip).map(|(_, m)| *m)
    }

    /// Records a reply, replacing the oldest entry when full.
    pub fn insert(&mut self, ip: Ip, mac: Mac) {
        if let Some(e) = self.entries.iter_mut().flatten().find(|(i, _)| *i == ip) {
            e.1 = mac;
            return;
        }
        self.entries[self.next] = Some((ip, mac));
        self.next = (self.next + 1) % self.entries.len();
    }
}

#[cfg(test)]
mod tests;
