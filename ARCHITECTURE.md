# lantern-network — Architecture

Companion to [wiki/Networking](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Networking.md). This layer *integrates*
proven privacy-preserving networking as OS services rather than reinventing it.

## Building blocks (research/direction)
| Capability | Approach | Prior art |
| --- | --- | --- |
| Authenticated encrypted channels | AEAD + KEX from [`lantern-crypto`](https://github.com/lantern-os/lantern-crypto) | Noise, TLS 1.3, WireGuard |
| Peer addressing & discovery | content/identity-addressed, DHT | libp2p, IPFS, Kademlia |
| Anonymous routing | onion routing | Tor |
| Metadata resistance | mixnets (batching, cover traffic) | Nym, Loopix |
| Censorship resistance | pluggable transports, relays | Tor bridges |
| Local connectivity | mesh / ad-hoc | Briar, Yggdrasil |
| Content distribution | content-addressed block exchange | IPFS/Bitswap |

## How it fits
- Confined user-space service; a compromise is bounded by its caps and it does **not** hold
  the keystore.
- Apps get **socket/endpoint capabilities** to specific destinations/identities — no ambient
  "open any connection".
- Network identities are backed by keys in [`lantern-crypto`](https://github.com/lantern-os/lantern-crypto) and relate
  to (but are separable from) [DIDs](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Identity.md).
- Shared content addressing with [`lantern-filesystem`](https://github.com/lantern-os/lantern-filesystem) makes peer
  exchange verifiable.

## The metadata spectrum
Offer a selectable trade-off per context — fast/authenticated (Noise-style) ⟷
slow/metadata-resistant (mixnet) — rather than forcing one point on the curve. The granting
capability encodes the choice.

## Open questions
- Mandatory baseline transport vs. optional modules.
- Making per-context identities genuinely unlinkable in practice.
- Privacy-preserving NAT traversal / discovery.
- Integrating a mixnet without operating central infrastructure.
- Offline/mesh store-and-forward.
- Anonymity vs. abuse-handling tension (documented, not hand-waved).
