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

## Non-goals
- Defeating a global passive adversary for *all* traffic at *low* latency (fundamental
  trade-off; we offer the mixnet option, not magic).
- Solving anonymity-vs-abuse perfectly (open social/technical problem).
