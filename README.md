# lantern-network

**Decentralised, peer-capable, anonymity-aware** networking. The network is treated as fully
hostile; the user controls how they appear on it, with **multiple, unlinkable network
identities** per context.

- **Layer:** system service (confined user space).
- **System context:** [wiki/Networking](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Networking.md).

> **Phase 3.** The first stack is built ([RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)/[ADR-0040](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0040-pairwise-network-identities.md)): IPv4 and UDP, in `lantern-boot`'s confined `net` service, under the
> wallet's pairwise identities. See [`STATUS.md`](./STATUS.md).

## In this repo
- **`lantern-network`**, a `no_std` crate with no allocation and no syscalls: Ethernet II, ARP, IPv4 and UDP, parsed and
  built. Everything from the network is hostile: a frame is dropped unless every length and checksum checks, and IP
  fragments, options past the header, broadcast or multicast sources and other hosts' traffic are all dropped.
  `cargo test` runs its host tests against hand-built and hostile frames.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Stance
Untrusted transport (endpoints establish security) · decentralised by default · protect
*metadata*, not just payloads · per-context network identities that resist correlation.
