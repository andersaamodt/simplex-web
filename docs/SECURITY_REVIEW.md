# Security Review

Date: 2026-05-12

Reviewer posture: Codex Desktop external-review simulation. This is not an
independent third-party human audit, but it was performed adversarially against
the code, tests, browser surface, and package metadata available in this local
environment.

## Scope

Reviewed release surface:

- `src/default-chat.js` and `src/default-chat.css`
- `src/session-store.js`
- `src/transport.js`
- `src/browser-smp-core.mjs`
- `src/browser-simplex-agent.mjs`
- `src/browser-simplex-client.mjs`
- `src/browser-simplex-contact-client.mjs`
- `src/browser-simplex-ratchet.mjs`
- `src/browser-simplex-scheduler.mjs`
- `src/browser-simplex-store.mjs`
- `src/browser-smp-server-profile.mjs`
- `src/browser-smp-websocket-transport.mjs`
- `src/browser-xftp-client.mjs`
- `src/browser-xftp-core.mjs`
- `src/browser-xftp-server-profile.mjs`
- Haskell/WASM scaffolds and runtime wrappers
- Browser examples and release documentation

Explicitly not shipped or reviewed as a release feature:

- A SimpleX Chat command API adapter.
- A loopback file bridge.
- A mock chat transport.
- A plaintext website/server bridge.
- Upstream SimpleX cryptographic protocol correctness.
- Live production browser SMP/XFTP server deployment.

## Threat Model

Primary assets:

- Browser-local chat history and draft state.
- SMP queue IDs, correlation IDs, signed transmissions, and broker responses.
- Browser-held signing, DH, and message encryption keys.
- Durable contact, queue, ratchet, skipped-message-key, and pending-send state.
- XFTP file root keys, manifests, ciphertext chunks, and plaintext file bytes.
- Ratcheted contact file descriptors that carry XFTP manifests and file root
  keys to the recipient.
- Contact invitation URIs, sender E2E DH keys, confirmation signing keys, and
  queue-securing `KEY` commands.
- Browser DOM integrity when rendering hostile imported messages or metadata.
- Package integrity, so removed plaintext paths cannot be imported accidentally.

Primary attacker capabilities tested:

- Inject hostile HTML, event handler strings, JavaScript URLs, oversized data,
  control characters, Unicode edge cases, and malformed attachment metadata.
- Poison browser storage and cached labels.
- Feed malformed SMP queue URIs, commands, broker messages, transport blocks,
  handshakes, encrypted envelopes, and correlation IDs.
- Feed hostile durable-storage keys and tamper with stored binary records.
- Reorder ratchet messages and tamper with ratchet ciphertext.
- Tamper with XFTP chunks, manifests, sizes, hashes, and server chunk responses.
- Downgrade production browser SMP server profiles to plaintext, wrong padding,
  missing origins, or missing session binding.
- Downgrade production browser XFTP server profiles to plaintext, missing
  origins, long retention, unsafe XFTP addresses, or plaintext chunk storage.
- Return malformed, short, long, text, wrong-session, or late WebSocket frames.
- Force browser rendering/layout stress across desktop and mobile viewports.

## Findings

### Fixed: legacy plaintext paths removed

The previous SimpleX Chat command WebSocket adapter, loopback file bridge, mock
chat example, and live daemon adapter tests are no longer shipped. The package
exports, runtime checks, README, architecture docs, changelog, and test scripts
now describe only the browser-native protocol workbench and closed transport
facade.

Coverage added:

- Runtime assertions that the removed adapter, file bridge, and mock example do
  not exist.
- Package assertions that no adapter or file-bridge export/script remains.
- A broad source scan during release cleanup for old command-API and bridge
  references.

### Fixed: browser protocol layers fail closed before side effects

The browser SimpleX client validates hostile correlation IDs before transport
send/receive side effects. The WebSocket SMP transport accepts only fixed-size
binary SMP blocks and rejects malformed frames, text frames, wrong-session
messages, and timeout paths.

### Fixed: browser client layers now own durable state and ratchets

The release now includes durable browser queue/contact/ratchet/pending-task
storage, a browser double-ratchet state machine, a contact lifecycle client,
bounded retry scheduling, XFTP-style encrypted chunk manifests, encrypted XFTP
upload/download sequencing, and production browser SMP/XFTP server profile
validation.

Coverage added:

- Durable store round trips binary records and rejects hostile storage keys.
- Ratchet tests cover out-of-order skipped messages and tampered ciphertext.
- Contact tests cover invitation creation, active ratcheted sends, inbound
  queue-message decrypt-and-ack, durable retry enqueueing after transport
  failure, and explicit retry draining.
- Contact request tests cover invitation URI generation, encrypted initial
  confirmation sends, profile hiding from broker bodies, recipient confirmation
  decrypt, queue `KEY` securing, ACK, and receiving-ratchet persistence.
- Contact file-transfer tests cover encrypted XFTP upload, ratcheted descriptor
  send, root-key hiding from the SMP body, received descriptor parsing, verified
  XFTP download, and received-file byte equality.
- E2E broker tests cover two browser clients exchanging ratcheted messages
  through queue creation, recipient `KEY`, signed `SEND`, encrypted received
  `MSG`, `ACK`, and forged-signature rejection.
- XFTP tests cover encrypted chunk reassembly, encrypted server-bound upload,
  verified download, deletion, profile downgrade rejection, and tampered chunk
  rejection.
- Server-profile tests reject plaintext URLs and missing session binding.
- Fuzz tests now cover hostile durable-store record IDs, hostile XFTP byte
  payload round trips with tamper rejection, unsafe browser SMP/XFTP server
  profile downgrades, hostile XFTP addresses, and encrypted XFTP client
  boundary round trips.

### Accepted residual risk: browser WebSocket SMP profile is not raw TCP/TLS SMP

Ordinary browser JavaScript cannot open raw TCP sockets, inspect TLS channel
binding, or pin server certificate bytes the same way a native SimpleX client
can. The current network-facing module is therefore an explicit browser
SMP-over-WebSocket profile for compatible servers, not a claim that browsers can
directly speak the existing raw TCP/TLS SMP transport.

### Accepted residual risk: live interoperability still needs real servers

The repo now contains browser-native SMP primitives, agent envelope helpers,
queue orchestration, contact state, durable ratchet storage, retry scheduling,
XFTP-style chunks, an encrypted-chunk XFTP client, and reviewed browser
SMP/XFTP server profile validators. It still needs live interoperability
vectors against real browser-profile SMP/XFTP servers before claiming production
network interoperability.

## Executed Coverage

Automated:

- `npm test`
- `npm run test:fuzz`
- `npm run test:browser`
- `npm run test:haskell`
- `npm audit --audit-level=moderate`
- `npm pack --dry-run --json`

Manual/browser:

- Safari automation probe using hostile message text, attachment metadata,
  textarea content, remote attachment URL, and viewport overflow check.

Toolchain:

- Official `ghc-wasm-meta` bootstrap completed into
  `/tmp/simplex-web-ghc-wasm`.
- `wasm32-wasi-ghc 9.14.1.20260330` and `wasm32-wasi-cabal 3.14.2.0` were
  verified from that environment.
- Haskell smoke and chat-core WASM runtime checks passed; see
  `docs/HASKELL_BROWSER_STATUS.md`.

## Release Posture

The release is suitable to describe as:

> adversarially tested by Codex Desktop across unit, integration, property/fuzz,
> browser, Safari automation, Haskell/WASM compile/runtime, packaging, and
> dependency audit coverage available in this environment.

Do not describe it as:

- complete full-stack browser SimpleX Chat
- direct browser support for existing raw TCP/TLS SMP/XFTP servers
- independently audited by a third-party security firm
- mathematically bulletproof
- free of all future protocol, browser, or upstream compatibility risk
