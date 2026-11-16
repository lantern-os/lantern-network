use super::*;

const MAC: Mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const IP: Ip = [10, 0, 2, 15];
const GW_MAC: Mac = [0x52, 0x55, 10, 0, 2, 2];
const GW: Ip = [10, 0, 2, 2];

fn route() -> Route {
    Route { mac: MAC, ip: IP, port: 40000, to_mac: GW_MAC, to_ip: GW, to_port: 7001 }
}

/// A datagram the gateway sends this host: `route` reversed.
fn incoming(payload: &[u8]) -> Vec<u8> {
    let r = route();
    let back = Route { mac: r.to_mac, ip: r.to_ip, port: r.to_port, to_mac: r.mac, to_ip: r.ip, to_port: r.port };
    let mut out = vec![0u8; FRAME_MAX];
    let n = udp(back, 7, payload, &mut out).unwrap();
    out.truncate(n);
    out
}

#[test]
fn the_checksum_is_rfc_1071s() {
    // RFC 1071's worked example: 0001 f203 f4f5 f6f7 sums to ddf2, so the checksum is 220d.
    assert_eq!(checksum(&[&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]]), 0x220d);
    // Split anywhere, odd lengths included, it's the same.
    assert_eq!(checksum(&[&[0x00, 0x01, 0xf2], &[0x03, 0xf4, 0xf5, 0xf6, 0xf7]]), 0x220d);
    // A well-known IPv4 header (Wikipedia's example) checks to zero.
    let h = [0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7];
    assert_eq!(checksum(&[&h]), 0);
}

#[test]
fn a_datagram_it_builds_parses_back_with_valid_checksums() {
    let frame = incoming(b"hello, lantern");
    assert_eq!(
        parse(&frame, MAC, IP),
        Some(Incoming::Udp { from: GW, from_port: 7001, to_port: 40000, payload: b"hello, lantern" })
    );
    assert_eq!(checksum(&[&frame[ETH_HEADER..ETH_HEADER + IP_HEADER]]), 0, "the IP header checks");
    // Empty and maximal payloads.
    assert!(matches!(parse(&incoming(b""), MAC, IP), Some(Incoming::Udp { payload: b"", .. })));
    let big = vec![0xab; UDP_MAX];
    assert!(matches!(parse(&incoming(&big), MAC, IP), Some(Incoming::Udp { payload, .. }) if payload.len() == UDP_MAX));
    assert_eq!(udp(route(), 0, &vec![0; UDP_MAX + 1], &mut [0u8; 2 * FRAME_MAX]), None, "over one datagram");
    assert_eq!(udp(route(), 0, b"x", &mut [0u8; 40]), None, "the buffer is too short");
}

#[test]
fn a_changed_byte_anywhere_in_a_datagram_drops_it() {
    let frame = incoming(b"payload");
    // Every byte of the IP and UDP headers and the payload, except the TTL and the IP ID, which the checksum covers too.
    for i in ETH_HEADER..frame.len() {
        let mut bad = frame.clone();
        bad[i] ^= 0x01;
        let parsed = parse(&bad, MAC, IP);
        assert!(
            !matches!(parsed, Some(Incoming::Udp { payload: b"payload", from_port: 7001, to_port: 40000, from: GW })),
            "byte {i} changed, and it still parsed the same"
        );
    }
}

#[test]
fn hostile_and_irrelevant_frames_are_dropped() {
    let good = incoming(b"x");
    let mut cases: Vec<(&str, Vec<u8>)> = vec![];
    let mut set = |name, f: &dyn Fn(&mut Vec<u8>)| {
        let mut c = good.clone();
        f(&mut c);
        cases.push((name, c));
    };
    set("short", &|c| c.truncate(ETH_HEADER + 10));
    set("for another host", &|c| c[0] = 0x02);
    set("from a multicast address", &|c| c[6] |= 1);
    set("not IPv4 or ARP", &|c| c[13] = 0xdd);
    set("IPv6 version", &|c| c[ETH_HEADER] = 0x65);
    set("a header length under 20", &|c| c[ETH_HEADER] = 0x44);
    set("a total length past the frame", &|c| {
        c[ETH_HEADER + 2] = 0x05;
        c[ETH_HEADER + 3] = 0xdc;
    });
    set("a fragment", &|c| c[ETH_HEADER + 6] = 0x20);
    set("a fragment offset", &|c| c[ETH_HEADER + 7] = 0x08);
    set("not UDP", &|c| c[ETH_HEADER + 9] = 6);
    set("for another address", &|c| c[ETH_HEADER + 19] = 16);
    set("a UDP length that disagrees", &|c| c[ETH_HEADER + IP_HEADER + 5] += 1);
    set("too long a frame", &|c| c.resize(FRAME_MAX + 1, 0));
    for (name, frame) in &cases {
        assert_eq!(parse(frame, MAC, IP), None, "{name}");
    }
    assert_eq!(parse(&[], MAC, IP), None);
}

/// A datagram built correctly, every checksum valid, for another host on the same network: dropped because of its
/// address, not because anything else is wrong with it.
#[test]
fn a_well_formed_datagram_for_another_host_is_dropped() {
    let r = route();
    let mut out = vec![0u8; FRAME_MAX];
    let to_other = Route { mac: r.to_mac, ip: r.to_ip, port: r.to_port, to_mac: MAC, to_ip: [10, 0, 2, 16], to_port: r.port };
    let n = udp(to_other, 1, b"not yours", &mut out).unwrap();
    // No UDP checksum, which IPv4 allows: its pseudo-header would cover the address too, and this is about the address.
    out[ETH_HEADER + IP_HEADER + 6..ETH_HEADER + IP_HEADER + 8].fill(0);
    assert_eq!(parse(&out[..n], MAC, [10, 0, 2, 16]).map(|_| ()), Some(()), "it's a valid datagram for 10.0.2.16");
    assert_eq!(parse(&out[..n], MAC, IP), None, "and not for this host");
}

#[test]
fn a_datagram_with_no_udp_checksum_is_taken_and_one_with_a_wrong_one_is_not() {
    let mut frame = incoming(b"abc");
    let at = ETH_HEADER + IP_HEADER + 6;
    frame[at] = 0;
    frame[at + 1] = 0;
    assert!(parse(&frame, MAC, IP).is_some(), "IPv4 allows no UDP checksum");
    frame[at + 1] = 1;
    assert_eq!(parse(&frame, MAC, IP), None);
}

#[test]
fn arp_requests_for_this_host_are_answered_and_replies_resolve() {
    let mut req = [0u8; 64];
    let n = arp_request(GW_MAC, GW, IP, &mut req);
    assert_eq!(parse(&req[..n], MAC, IP), Some(Incoming::ArpRequest { mac: GW_MAC, ip: GW }));
    assert_eq!(parse(&req[..n], MAC, [10, 0, 2, 99]), None, "a request for another address");
    let mut rep = [0u8; 64];
    let n = arp_reply(GW_MAC, GW, MAC, IP, &mut rep);
    assert_eq!(parse(&rep[..n], MAC, IP), Some(Incoming::ArpReply { mac: GW_MAC, ip: GW }));
    // A reply whose sender disagrees with the frame's source is dropped.
    let mut spoof = rep;
    spoof[6] = 0x02;
    assert_eq!(parse(&spoof[..n], MAC, IP), None);
    let mut cache = ArpCache::default();
    assert_eq!(cache.get(GW), None);
    cache.insert(GW, GW_MAC);
    assert_eq!(cache.get(GW), Some(GW_MAC));
    for i in 0..20u8 {
        cache.insert([10, 0, 2, 100 + i], [i; 6]);
    }
    assert_eq!(cache.get([10, 0, 2, 119]), Some([19; 6]), "the newest stays");
    assert_eq!(cache.get(GW), None, "the oldest went");
}

#[test]
fn off_the_subnet_goes_through_the_gateway() {
    assert_eq!(next_hop(IP, GW, [10, 0, 2, 3]), [10, 0, 2, 3]);
    assert_eq!(next_hop(IP, GW, [192, 168, 1, 1]), GW);
}
