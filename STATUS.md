# lantern-network — Status

**Phase:** 3 (Privacy, identity, networking, and AI) — opened per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md). The first stack and the pairwise identities over it are built (RFC-0035).

## Done
- Building-block survey and integration stance drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Metadata-spectrum approach and threat model drafted and reviewed.

- **IPv4/UDP and pairwise network identities (2026-11-16, [RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)/[ADR-0040](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0040-pairwise-network-identities.md)).** This
  crate: Ethernet, ARP, IPv4 and UDP, `no_std`, no allocation, 8 host tests (RFC 1071's checksum example, round trips,
  every single-byte change to a datagram, hostile and irrelevant frames, a well-formed datagram for another host, ARP). `lantern-boot`'s `net-driver`, `net` and
  `wallet` run it confined, and `net-matrix.sh` proves the exit criterion against two host peers using `snow`.

## Next
- Prior-art deep-dive: libp2p, Tor, Nym/Loopix, Briar (write up trade-offs).
- Choose the mandatory baseline transport.
- DHCP and DNS; TCP when something needs it.
- P2P discovery; a first anonymity transport, so the network can't link contexts either.

## Blocked on
- An IOMMU, to confine the network driver's DMA ([`lantern-hal`](https://github.com/lantern-os/lantern-hal)).
