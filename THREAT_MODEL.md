# lantern-network — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). The adversary here
includes a fully capable network attacker and a metadata-correlating surveillor
(system threats T5, plus the network-attacker row).

## Assets
- Confidentiality & integrity of communications.
- **Metadata privacy** (who talks to whom, when, how much).
- Unlinkability of a user's per-context network identities.
- Availability under censorship.

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| N1 | Eavesdrop/modify/inject traffic | End-to-end AEAD + authenticated KEX; integrity from endpoints, not transport. |
| N2 | Correlate a user across services via metadata | Per-context identities; onion routing; mixnet option; metadata minimisation. |
| N3 | Malicious peer / Sybil in discovery | Authenticated peers; reputation/limits; content addressing verifies data regardless of source. |
| N4 | Compromised network service reaches user keys/data | Confined service; no keystore access; socket caps scoped to destinations. |
| N5 | Censorship / blocking | Pluggable transports, relays, mesh fallback. |
| N6 | Traffic-analysis deanonymisation | Cover traffic + batching (mixnet) where the context selects it; documented limits. |

## As built (RFC-0035)
- **The stack parses hostile input and holds nothing:** `net` has no key, no DMA, no store and no console, and serves only
  the wallet. Its parser is host-tested against every single-byte change to a datagram, fragments, bad lengths and
  checksums, and spoofed ARP.
- **Linkage by keys** is prevented: each (app, peer) gets an identity derived from a root only the wallet holds.
- **Linkage by the network** isn't: one IP address for every context, and timing. Stated, not hidden.
- **ARP and datagrams can be forged** on the local network: a forged peer can't complete a Noise handshake as the real one
  (`net-matrix.sh`'s forged-handshake case), and a forged datagram in a session doesn't authenticate.
- **The driver has DMA** until there's an IOMMU (RFC-0023's checklist).
- **Randomness comes from the host** in QEMU (virtio-rng): a malicious host could predict ephemeral keys. RFC-0023's
  checklist carries it.

## Non-goals
- Defeating a global passive adversary for *all* traffic at *low* latency (fundamental
  trade-off; we offer the mixnet option, not magic).
- Solving anonymity-vs-abuse perfectly (open social/technical problem).
