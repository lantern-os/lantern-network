# lantern-network — Architecture

Companion to [wiki/Networking](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Networking.md). This layer *integrates*
proven privacy-preserving networking as OS services rather than reinventing it.

## As built ([RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)/[ADR-0040](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0040-pairwise-network-identities.md))

```
 app ──identity context──► wallet ──UDP──► net ──frames──► net-driver ──virtio──► network
       (no key, no socket)   (every key,     (IPv4/UDP,      (DMA, parses
                              Noise XX)       no key)          nothing)
```

- **`net-driver`** (`lantern-boot`): virtio-net. Whole frames to and from one client; it parses none. Trusted with memory
  until there's an IOMMU, like the block driver. Its interrupt goes to `net`'s notification.
- **`net`** (`lantern-boot`, around this crate): ARP and a static IPv4 address; UDP for one client, the wallet, on its
  ports only. It holds no key: compromised, it can read ciphertext and drop or forge datagrams, which the sessions detect.
- **The wallet** (`lantern-boot`): one root; a pairwise X25519 identity per (app, peer) from keyed BLAKE3 of it
  (`lantern-crypto::pairwise`); Noise `XX` sessions (`lantern-crypto::noise`). Apps hold a context capability, never a
  key, an address or a socket.
- **Today's place on the metadata spectrum** (below): authenticated and encrypted, fast, and *not* metadata-resistant.
  Both of an app's peers see the same IP address, and when it talks.

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
