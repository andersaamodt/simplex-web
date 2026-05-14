# Changelog

## 1.0.1 - 2026-05-14

- Removed the previous SimpleX Chat command API adapter, loopback file bridge,
  mock chat example, and live adapter tests so the package no longer ships a
  daemon-backed or plaintext compatibility path.
- Removed loopback attachment URL autoloading from the default chat renderer so
  imported history cannot force browser fetches to local services.
- Removed package exports, scripts, runtime checks, and README instructions for
  that deleted compatibility path.
- Added `src/browser-smp-core.mjs`, the first handwritten browser-native SMP protocol core slice.
- Added SMP queue URI parsing, command/broker-message codecs, signed transmission framing, fixed-size transport block padding, SMP v4 batching, and handshake helpers.
- Added browser-compatible Ed25519, X25519, XSalsa20-Poly1305, AES-GCM, and SHA-256 helpers through audited Noble JavaScript crypto packages.
- Added focused unit and fuzz coverage for the SMP core.
- Added `src/browser-simplex-agent.mjs`, the first browser-native SimpleX agent helper layer for encrypted client-message envelopes, queue creation, queue-scoped recipient commands, and initial sender confirmation messages.
- Added focused unit and fuzz coverage for the browser agent helper layer.
- Added `src/browser-simplex-client.mjs`, a queue-level browser SimpleX client orchestrator over abstract SMP transports.
- Added per-queue SMP transport routing so native reply queues on different
  relays receive their own SKEY/SEND/ACK/DEL commands instead of being sent to
  the original contact-address relay.
- Added focused client tests for signed `NEW`, `SUB`, `ACK`, `KEY`, `DEL`, unsigned initial confirmation, broker errors, and hostile correlation IDs.
- Added `src/browser-smp-websocket-transport.mjs`, a binary SMP-over-WebSocket browser transport profile for compatible SMP servers.
- Added `src/browser-smp-native-tls-relay.mjs`, a Node-side native TLS SMP byte
  relay for local/server-side interop with existing native SMP relays without
  exposing SimpleX Chat plaintext.
- Advanced live Owl interop through contact request, native accept decrypt,
  per-relay SKEY, native HELLO, and broker-accepted SEND. Readable post-accept
  Owl chat still returns `AGENT A_MESSAGE` and remains open.
- Added focused transport tests for URL policy, binary handshakes, block sending/receiving, malformed frames, and session mismatch handling.
- Added live loopback WebSocket SMP transport coverage using a real local WebSocket upgrade server and Node's browser-compatible WebSocket client.
- Added `src/browser-simplex-store.mjs` for durable browser queue, contact, ratchet, and pending-task state.
- Added `src/browser-simplex-ratchet.mjs` for browser-owned double-ratchet message encryption, skipped-message keys, and tamper rejection.
- Added `src/browser-simplex-contact-client.mjs` for contact lifecycle, active-contact sends, inbound decrypt-and-ack receive handling, ratchet persistence, and failed-send retry enqueueing/draining.
- Added contact-client invitation URI, encrypted contact request, request receive, queue secure, and ACK handling.
- Added requester reply queues, encrypted accept-confirmation receive handling, and a requester-first post-accept ratchet regression to complete more of the two-sided contact bootstrap.
- Added durable encrypted initial-contact retry handling so failed contact requests can be resent without storing profile plaintext.
- Added durable encrypted accept-confirmation retry handling so inbound contact acceptance survives transport failure after request ACK.
- Added durable ACK retry handling so inbound messages are not lost if decrypt succeeds but the queue ACK transport round-trip fails.
- Added durable ACK retry handling for received accept confirmations so requester activation survives ACK transport failure.
- Added durable ACK retry handling for received contact requests so recipient activation and accept-send can survive request ACK transport failure.
- Added metadata-only received-message fingerprints so duplicate SMP redelivery is ACKed without replaying the ratchet or redelivering plaintext, while same-id changed-body replay fails closed.
- Hardened inbound contact receive so malformed higher-level payloads cannot persist a ratchet advance before ACK/fingerprint side effects.
- Hardened outbound contact sends so missing/corrupt queue state fails before consuming a sending ratchet step.
- Changed retry records for encrypted send packets and initial contact requests to store binary bytes instead of truncation-prone strings.
- Changed failed-send retries to persist the already-ratcheted packet bytes instead of chat plaintext.
- Changed capped durable-store record lists to keep newest saved IDs visible when the list reaches its retention limit.
- Added full-scan durable-store deletion so privacy cleanup can scrub records that have fallen out of capped visible lists.
- Hardened durable-store cleanup against poisoned list metadata and corrupt scanned records.
- Added contact deletion scrubbing for durable queue records, ratchet state, received-message fingerprints, and contact-scoped retry payloads.
- Expanded contact deletion fuzzing to cover received-message fingerprint cleanup.
- Added remote-first contact deletion that sends signed SMP `DEL` for browser-owned inbox queues before local cleanup and preserves local secrets if broker deletion fails.
- Exposed remote-first contact deletion through the first-party adapter and `window.SimplexWebTransport.deleteContact(...)`.
- Added contact-client XFTP file send/receive helpers that upload encrypted chunks, ratchet-send file descriptors/root keys, and verify received downloads.
- Added encrypted read receipts across the contact client, first-party adapter,
  and public facade so Secure Chat can move outgoing messages from sent to read
  without exposing receipt metadata to the website server or SMP broker.
- Added `src/browser-simplex-scheduler.mjs` for bounded retry scheduling.
- Added `src/browser-simplex-web-transport-adapter.mjs`, a first-party adapter that registers the browser contact client with `window.SimplexWebTransport` over SMP WebSocket and optional XFTP web file transfer.
- Added `src/browser-xftp-core.mjs` for XFTP-style encrypted chunk manifests, tamper detection, and download assembly.
- Added `src/browser-smp-server-profile.mjs` for reviewed production browser SMP server profile validation.
- Added `src/browser-xftp-client.mjs` and `src/browser-xftp-server-profile.mjs` for encrypted XFTP chunk upload/download sequencing and production browser XFTP server profile validation.
- Added `src/browser-xftp-http-transport.mjs` and live loopback fetch coverage for encrypted XFTP chunk upload, download, and deletion.
- Added `src/browser-xftp-web-client.mjs`, an upstream-style browser XFTP web client for binary fetch hello, server identity proof verification, padded handshake, PING, authenticated FNEW/FPUT/FGET/FDEL command wrappers, file-level envelope encryption, deterministic chunk planning, strict text file-description serialization with wrong-party/wrong-server rejection, upload/download/delete assembly, and transport-encrypted FGET chunk decryption.
- Added deterministic local interoperability vectors for SMP command/broker/handshake bytes, signed transmissions, agent envelopes, and XFTP chunks.
- Added a skipped-by-default live SMP/XFTP interoperability harness and `docs/LIVE_INTEROP.md` so reviewed browser-profile endpoints can be tested without adding flaky network work to the default suite.
- Added focused adversarial tests and fuzz/property coverage for storage keys, ratchet tampering, contact retries, inbound contact receive/ack, XFTP corruption, hostile XFTP byte payloads, encrypted XFTP client boundaries, scheduler bounds, and SMP/XFTP server-profile downgrade rejection.
- Added an in-process browser-profile SMP broker E2E test for two browser clients, signed sends, encrypted received messages, ACKs, and forged-signature rejection.

## 1.0.0 - 2026-05-11

- Stabilized the framework-free Secure Chat UI renderer and mount contract.
- Stabilized bounded browser-local session persistence.
- Added a closed-by-default `window.SimplexWebTransport` facade with explicit adapter registration.
- Hardened delegated UI click handling so actions resolved outside the mounted root are ignored.
- Kept plaintext server bridge fallback out of the transport path.
- Added focused adversarial input coverage for UI rendering, session storage, transport normalization, browser-native protocol boundaries, and Safari/WebKit rendering behavior.
- Added the 2026-05-11 external-review-style security review notes in `docs/SECURITY_REVIEW.md`.
- Proved the Haskell/WASM smoke and chat-core checks against `ghc-wasm-meta`'s `wasm32-wasi-ghc`.

Not included in `1.0.0`:

- Direct browser support for existing raw TCP/TLS SMP/XFTP servers.
- Checked-in Haskell/WASM build artifacts.
