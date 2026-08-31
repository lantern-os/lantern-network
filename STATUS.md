# lantern-network — Status

**Phase:** 3 (Privacy, identity, networking, and AI) — opened per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md). Still research/design only — see "Blocked on".

## Done
- Building-block survey and integration stance drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Metadata-spectrum approach and threat model drafted and reviewed.

## Next
- Prior-art deep-dive: libp2p, Tor, Nym/Loopix, Briar (write up trade-offs).
- Choose the mandatory baseline transport.
- Phase 3: authenticated encrypted channel + P2P discovery; first anonymity transport.

## Blocked on
- **The confined-execution port carried forward from Phase 2 (ADR-0021).** A capability-scoped socket has to be reachable from a confined component the way `lantern:host/keystore` and `lantern:host/filesystem` already are (RFC-0014/RFC-0016). The services and `lantern-runtime` must run as separate confined processes on the kernel, not host-target stand-ins. That port is Phase 3's first work; this crate follows it.
- Crypto channel primitives ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).
- Capability-scoped sockets ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).
- Identity/DID design ([`lantern-docs/wiki/Identity`](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md)).
