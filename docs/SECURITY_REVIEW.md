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
- `src/browser-simplex-web-transport-adapter.mjs`
- `src/browser-smp-server-profile.mjs`
- `src/browser-smp-native-tls-relay.mjs`
- `src/browser-smp-websocket-transport.mjs`
- `src/browser-xftp-client.mjs`
- `src/browser-xftp-core.mjs`
- `src/browser-xftp-server-profile.mjs`
- `src/browser-xftp-web-client.mjs`
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
- Compare deterministic wire-format vectors against current encoders and parse
  the committed fixtures back through decoders.
- Feed hostile durable-storage keys and tamper with stored binary records.
- Reorder ratchet messages and tamper with ratchet ciphertext.
- Tamper with XFTP chunks, manifests, sizes, hashes, and server chunk responses.
- Exercise real loopback `fetch` upload, download, and deletion for encrypted
  XFTP chunks without exposing plaintext bytes to request bodies.
- Exercise upstream-style XFTP web binary fetch handshake, identity proof
  verification, PING, authenticated file-command wrappers, and
  transport-encrypted download chunk verification.
- Serialize and parse XFTP web file descriptions with bounded, strict text
  parsing, party checks, contiguous chunk-plan checks, and connected-server
  matching before descriptor text is accepted for download or deletion.
- Exercise first-party `window.SimplexWebTransport` adapter sends, file sends,
  receive polling, and in-process browser-contact E2E delivery.
- Provide a skipped-by-default live interop harness for reviewed non-loopback
  SMP/XFTP browser-profile endpoints.
- Route queue commands to the SMP relay that owns the queue, including native
  SimpleX accept replies where the reply queue is on a different relay.
- Exercise a local live SimpleX Chat/Owl interop run through contact request,
  accept decrypt, per-relay SKEY, reply-queue confirmation, client-message
  wrapped SEND, broker-accepted SEND, and Owl `newChatItems` text delivery
  without exposing chat plaintext to the relay.
- Downgrade production browser SMP server profiles to plaintext, wrong padding,
  missing origins, or missing session binding.
- Downgrade production browser XFTP server profiles to plaintext, missing
  origins, long retention, unsafe XFTP addresses, or plaintext chunk storage.
- Return malformed, short, long, text, wrong-session, or late WebSocket frames.
- Exercise real loopback WebSocket upgrade, masked client frames, binary server
  frames, SMP handshake, client block send, and broker response receive.
- Force browser rendering/layout stress across desktop and mobile viewports.

## Findings

### Fixed in local live run: native Owl post-accept text delivery

The browser can now send the contact request to Owl, decrypt Owl's native accept,
route the reply queue to the correct SMP relay, secure that queue with SKEY,
send the reply-queue confirmation that establishes Owl's E2E key, and deliver a
post-accept text message that Owl stores as `newChatItems`. The relay still only
sees encrypted SMP blocks.

### Open: native Owl feature parity is not complete

The successful local live pass covers browser-to-Owl text delivery. Native file
attachments, native read receipts, longer bidirectional conversations, and
browser receipt/receive handling against Owl still need live passes before
claiming broader SimpleX Chat/Owl compatibility.

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
- Durable store retention tests prove capped record lists keep newest saved
  IDs visible instead of silently hiding newly saved records.
- Durable store cleanup tests prove `deleteWhere` finds records that have fallen
  out of capped visible lists by scanning the physical storage keyspace.
- Durable store cleanup tests prove malformed same-origin storage keys and
  corrupt scanned records do not block cleanup of valid records.
- Durable store cleanup tests prove poisoned list metadata can be recovered and
  corrupt scanned records can be deleted intentionally during cleanup.
- Ratchet tests cover out-of-order skipped messages and tampered ciphertext.
- Contact tests cover invitation creation, active ratcheted sends, inbound
  queue-message decrypt-and-ack, encrypted-packet retry enqueueing after
  transport failure, explicit retry draining, and contact deletion that scrubs
  durable queue records, ratchet secrets, received-message fingerprints, and
  contact-scoped pending retry payloads.
- Queue routing tests prove sender-side commands for a queue on another SMP
  relay use the configured per-server transport instead of the original contact
  relay.
- Remote-first contact deletion tests prove browser-owned inbox queues receive
  signed SMP `DEL` before local scrubbing, local secrets remain if the remote
  delete fails, and hostile stored inbox IDs fall back to the safe default.
- Facade and adapter tests prove `window.SimplexWebTransport.deleteContact()`
  is unavailable without a browser adapter, normalizes deletion requests, and
  reaches the contact client's remote-first deletion path.
- Contact deletion fuzzing now includes received-message fingerprint records so
  hostile metadata cases exercise the same privacy cleanup path, including
  corrupt received-record cleanup.
- Failed-send tests prove retry records contain the already-ratcheted packet
  bytes as binary storage records, do not contain the outbound plaintext, and
  resend the same encrypted packet during retry drain.
- Initial contact retry tests prove failed encrypted contact requests keep a
  requested contact, durable queues, and ratchet state, persist only the
  already-encrypted unsigned SMP `SEND`, avoid profile plaintext, and resend
  the same encrypted envelope during retry drain.
- Accept-confirmation retry tests prove an inbound request that has already
  been secured and ACKed saves active contact state, durable outbox queue, and
  receiving ratchet state before a failed accept send is retried as encrypted
  bytes without profile plaintext.
- Missing-queue send tests prove corrupt outbound contact state fails before
  consuming a sending ratchet step or creating a retry task.
- Replay tests cover duplicate received-message IDs with identical encrypted
  bodies, proving they are ACKed without ratchet replay or plaintext
  redelivery, and changed-body replays, proving no ACK side effect happens.
- Malformed payload tests cover successful ratchet decrypt followed by
  higher-level payload rejection, proving the ratchet advance is not persisted
  before ACK/fingerprint side effects.
- ACK-failure tests cover decrypt-success/ACK-failure ordering, prove the
  plaintext is returned to the caller, persist only a non-plaintext ACK retry
  task, and complete that ACK through the retry drain.
- Accept-confirmation ACK-failure tests prove requester activation is saved
  before a failed ACK is retried as a non-plaintext ACK task.
- Contact-request ACK-failure tests prove recipient activation, receiving
  ratchet state, and accept-send can complete while the failed request ACK is
  retried as a non-plaintext ACK task.
- Contact request tests cover invitation URI generation, requester reply-queue
  creation, caller-supplied reply-queue persistence, encrypted initial
  confirmation sends, profile hiding from broker bodies, recipient confirmation
  decrypt, encrypted accept-confirmation sends, requester accept-confirmation
  decrypt, queue `KEY` securing, ACK, and receiving-ratchet persistence.
- Malformed reply-queue tests cover imported contact-request metadata before
  queue `KEY`, ACK, accept-send, or contact-state side effects are allowed.
- Full bootstrap regression covers request, accept, requester first ratcheted
  message delivery, recipient decrypt, and ACK, so the recipient cannot persist
  a half-initialized receiving ratchet after accepting a request.
- Contact file-transfer tests cover encrypted XFTP upload, ratcheted descriptor
  send, root-key hiding from the SMP body, received descriptor parsing, verified
  XFTP download, and received-file byte equality.
- Read-receipt tests cover sender message refs inside ratcheted text/file
  payloads, encrypted receipt sends that do not expose the target message ref in
  the SMP body, receipt receive parsing, facade normalization, and adapter E2E
  status updates from `sent` to `read`.
- E2E broker tests cover two browser clients exchanging ratcheted messages
  through queue creation, recipient `KEY`, signed `SEND`, encrypted received
  `MSG`, `ACK`, and forged-signature rejection.
- First-party facade-adapter tests cover `sendText`, `sendFiles`,
  `sendReadReceipt`, `getMessages`, registration with
  `window.SimplexWebTransport`, and an in-process ratcheted contact
  send/receive/read-receipt cycle over the browser SimpleX contact client.
- XFTP tests cover encrypted chunk reassembly, encrypted server-bound upload,
  verified download, deletion, profile downgrade rejection, and tampered chunk
  rejection.
- Live loopback XFTP HTTP tests cover actual `fetch` transport behavior and
  verify server request bodies contain encrypted chunk packets, not plaintext
  file bytes.
- XFTP web loopback tests cover padded browser hello, server identity proof
  verification, padded client handshake, PING, authenticated FNEW/FPUT/FGET/FDEL
  command blocks, file-level envelope encryption, deterministic chunk planning,
  strict file-description serialization/parsing, encrypted file
  upload/download/delete assembly, transport-encrypted FGET body decryption,
  digest mismatch rejection, malformed descriptor rejection, wrong-party
  descriptor rejection before side effects, wrong-server descriptor rejection
  before side effects, ciphertext tamper rejection, path smuggling rejection,
  and explicit rejection of missing identity proof outside loopback test mode.
- Local interoperability-vector tests cover stable SMP command/broker/handshake,
  signed transmission, transport-block, agent-envelope, and XFTP fixture bytes.
- Live loopback WebSocket tests cover actual WebSocket framing around the
  browser SMP transport profile without reintroducing a plaintext bridge.
- Skipped-by-default live interop tests define the required non-loopback proof
  for browser-profile SMP WebSocket PING/PONG and upstream-style XFTP web
  HTTPS handshake, identity proof, and PING/PONG. A second opt-in destructive
  live XFTP test uploads, downloads, decrypts, verifies, and deletes a
  disposable encrypted file when `SIMPLEX_WEB_LIVE_XFTP_DESTRUCTIVE=1`.
- Server-profile tests reject plaintext URLs and missing session binding.
- Fuzz tests now cover hostile durable-store record IDs, hostile XFTP byte
  payload round trips with tamper rejection, unsafe browser SMP/XFTP server
  profile downgrades, hostile XFTP addresses, hostile facade adapter inputs
  before contact side effects, hostile XFTP web descriptor text, and encrypted
  XFTP client boundary round trips.

### Accepted residual risk: browser WebSocket SMP profile is not raw TCP/TLS SMP

Ordinary browser JavaScript cannot open raw TCP sockets, inspect TLS channel
binding, or pin server certificate bytes the same way a native SimpleX client
can. The current network-facing module is therefore an explicit browser
SMP-over-WebSocket profile for compatible servers, not a claim that browsers can
directly speak the existing raw TCP/TLS SMP transport.

### Accepted residual risk: live interoperability still needs real servers

The repo now contains browser-native SMP primitives, agent envelope helpers,
queue orchestration, contact state, durable ratchet storage, retry scheduling,
XFTP-style chunks, an encrypted-chunk XFTP client, an upstream-style XFTP web
client with file envelope assembly, and reviewed browser SMP/XFTP server
profile validators. It also
contains a skipped-by-default live interop harness in
`tests/live-interop.test.mjs`. It still needs that harness to pass against
reviewed browser-profile SMP/XFTP servers and upstream-certified SimpleX
fixture bytes before claiming production network interoperability.

## Executed Coverage

Automated:

- `npm test`
- `npm run test:fuzz`
- `npm run test:browser`
- `npm run test:live` with no live endpoint variables, which verifies the
  skipped-by-default harness path
- `npm run test:haskell`
- `npm audit --audit-level=moderate`
- `npm pack --dry-run --json`

Manual/browser:

- Safari automation probe using hostile message text, attachment metadata,
  textarea content, remote/loopback attachment URLs, and viewport overflow
  check.

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
