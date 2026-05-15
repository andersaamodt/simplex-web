# Architecture

## Reader map

`simplex-web` is built as a small set of plain modules rather than as a
framework app:

1. `src/default-chat.js` renders the chat UI from a plain data model and emits
   callbacks when the user clicks, types, sends, or selects files.
2. `src/session-store.js` keeps a bounded local browser cache of UI continuity
   state such as drafts, recent messages, and upload rows.
3. `src/browser-smp-core.mjs` is the first handwritten browser-native SMP
   protocol slice. It owns binary encodings, queue URI parsing, command codecs,
   signed transmissions, 16384-byte transport blocks, v4 batching, handshakes,
   and browser-compatible crypto primitives.
4. `src/browser-simplex-agent.mjs` is the first browser-native SimpleX agent
   helper slice. It owns client-message envelopes, confirmation headers,
   received-message body encryption, queue creation state, queue-scoped
   recipient commands, and unsigned initial sender confirmation messages.
5. `src/browser-simplex-client.mjs` is a small queue-level client orchestrator
   over an abstract SMP transport. It performs create, subscribe, acknowledge,
   secure, delete, and initial confirmation protocol flows.
6. `src/browser-simplex-store.mjs` persists queue, contact, ratchet, and
   pending-task records in a Storage-like browser backend. Visible lists are
   capped, poisoned list metadata is recovered, and cleanup paths can scan
   physical storage keys for full deletion.
7. `src/browser-simplex-ratchet.mjs` owns the browser double-ratchet state:
   root keys, DH steps, sending/receiving chains, skipped-message keys, and
   message AEAD.
8. `src/browser-simplex-contact-client.mjs` combines the queue client, store,
   ratchet, and scheduler into a contact lifecycle client.
9. `src/browser-simplex-scheduler.mjs` computes bounded retry schedules for
   transient/offline work.
10. `src/browser-simplex-web-transport-adapter.mjs` is the first-party adapter
   that registers the browser contact client with `window.SimplexWebTransport`.
   It exposes send, receive, contact setup, retry drain, and remote-first
  contact deletion operations. It also keeps encrypted read-receipt state for
  messages sent through the facade.
11. `src/browser-xftp-core.mjs` owns encrypted XFTP-style chunks, manifests, and
   reassembly verification.
12. `src/browser-xftp-client.mjs` owns encrypted chunk upload/download
   sequencing against a reviewed browser XFTP server boundary.
13. `src/browser-xftp-server-profile.mjs` validates production browser XFTP
   server profiles before encrypted file chunks are uploaded or downloaded.
14. `src/browser-xftp-web-client.mjs` implements the upstream-style browser
   XFTP web profile: binary fetch transport, web challenge, identity proof,
   padded handshake, PING, authenticated file-command wrappers, serializable
   file descriptions, and file-level encrypted upload/download assembly with
   transport-encrypted download chunk verification.
15. `src/browser-smp-server-profile.mjs` validates production browser SMP server
   profiles before a browser endpoint is trusted.
16. `src/browser-smp-websocket-transport.mjs` is the first network-facing browser
   transport profile. It sends and receives one padded binary SMP block per
   WebSocket frame for compatible SMP servers.
17. `src/transport.js` is the public browser API. It is unavailable until an
   adapter is registered, so host pages cannot accidentally send plaintext
   through a server fallback.
18. `haskell/src/Simplex/Web/*.hs` proves the Haskell-to-browser boundary with a
   small state core and a smoke module; it is not yet the network protocol core.

The shape is intentionally conservative: the UI can be embedded on any page, the
transport boundary fails closed, and the code can be tested in Node, browsers,
Safari automation, and wasm GHC without a bundler.

## Current boundary

`simplex-web` currently owns the browser-facing chat shell, the first Haskell-owned chat-state slice, and the first handwritten SMP protocol primitive layer:

- HTML rendering for a single-thread secure chat surface
- message/status presentation
- upload progress presentation
- framework-free DOM mounting and event delegation
- bounded browser-local persistence for per-user chat continuity on the same browser/device
- UI callback surface for login, send, file-select, and admin actions
- Haskell-managed local chat state transitions exposed through browser-callable wasm exports
- SMP queue/server URI parsing
- SMP `Encoding`-style byte helpers for fixed-width integers, length-prefixed bytes, and base64url strings
- SMP command and broker-message codecs for queue creation, subscription, send, acknowledgement, notification subscription, and server responses
- Signed SMP transmission encoding/parsing and Ed25519 signature verification over the exact signed bytes
- SMP v3/v4 transport block padding, unpadding, and v4 batched transmission framing
- SMP handshake encoders/decoders and compatible-version selection
- Browser-compatible Ed25519, X25519, XSalsa20-Poly1305, AES-GCM, and SHA-256 helpers
- SimpleX client-message public/private headers and encrypted envelopes
- SimpleX confirmation messages carrying the sender SMP signing key inside the encrypted body
- received-message body encryption/decryption with timestamp and notification flag metadata
- queue creation helpers for signed `NEW`, `IDS` completion, signed `SUB`/`ACK`, and initial unsigned sender `SEND`
- queue-level client orchestration over abstract SMP transports for create, subscribe, acknowledge, secure, delete, and initial confirmation
- durable browser queue, contact, ratchet, and pending-task storage
- browser double-ratchet root/chain key progression, skipped-message keys, and AEAD packet encryption
- contact lifecycle states for invited, requested, active, suspended, and deleted contacts
- browser invitation URI creation, requester reply queues, encrypted sender
  contact requests, encrypted accept confirmations, recipient/requester
  confirmation-key verification, queue `KEY` securing, and request/accept ACKs
- active-contact sends and receives with ratchet persistence, SMP ACKs, durable ACK retry, duplicate-redelivery suppression, changed-body replay rejection, encrypted read receipts, and encrypted-packet failed-send retry enqueueing
- contact file sends that upload encrypted XFTP chunks and send only the file descriptor/root key through the ratcheted contact channel
- native SimpleX file sends that batch the `x.msg.new` file invitation and
  `x.msg.file.descr` YAML descriptor parts in one encrypted agent message, which
  matches the shape Owl Native expects for XFTP invitations
- contact file receives that download and verify encrypted XFTP chunks after the descriptor arrives through the ratcheted contact channel
- in-process browser-profile SMP broker E2E coverage for two browser clients, signed sends, encrypted received messages, ACKs, and forged-signature rejection
- bounded retry scheduling with deterministic testable backoff
- XFTP-style encrypted file chunk manifests, chunk authentication, and download assembly
- encrypted XFTP chunk upload/download sequencing over a reviewed server boundary
- browser SMP server profile validation for binary frames, origin policy, padding, and session-binding requirements
- browser XFTP server profile validation for encrypted chunk storage endpoints
- upstream-style browser XFTP web hello, identity-proof verification, padded handshake, PING, authenticated FNEW/FPUT/FGET/FDEL command wrappers, file-level envelope encryption, deterministic chunk planning, strict text file-description serialization, upload/download/delete helpers, and transport-encrypted FGET chunk decryption
- SMP-over-WebSocket URL validation, binary handshake handling, 16 KiB frame enforcement, block send, and block receive
- per-queue SMP transport routing, so reply queues on different relays use their owning relay for SKEY/SEND/ACK/DEL instead of leaking through one fixed connection
- a Node-side native SMP TLS byte relay for encrypted-block interop with existing relays during local/server-side deployments
- live loopback WebSocket coverage for browser transport handshake, masked client frames, binary SMP blocks, and broker responses
- skipped-by-default live SMP/XFTP interoperability coverage for reviewed non-loopback browser-profile endpoints
- live Firefox-to-Owl Native Secure Chat coverage on the production Secure Chat
  deployment for browser-to-Owl text and XFTP file sending
- a closed-by-default `window.SimplexWebTransport` facade for host-site integration
- a first-party facade adapter that wires the browser contact client to SMP WebSocket and optional XFTP web transport

It intentionally does **not** ship old or unsafe compatibility paths:

- no SimpleX Chat command API adapter
- no loopback file bridge
- no mock chat transport
- no plaintext website/server bridge
- no production direct browser-JavaScript transport to existing raw TCP/TLS SMP servers yet; the current browser transport is a WebSocket SMP profile for compatible servers, and the native TLS relay is a server-side encrypted byte adapter rather than a plaintext bridge

## Wizardry Ethos Fit

The project is intentionally low to the ground:

- source is plain JavaScript/ESM and Haskell source, not a framework app
- protocol code works directly with bytes and documented wire shapes
- browser storage and transport boundaries are explicit instead of hidden behind a hosted service
- runtime dependencies are limited to audited free-software crypto packages where hand-rolling would be a security downgrade
- project code is `AGPL-3.0-only`, and current runtime/test dependencies are MIT, Apache-2.0, or MIT/Apache-2.0
- generated build outputs, logs, and local runtime state stay out of the repo

The design rule is that `simplex-web` should remain inspectable by reading a few
small files. New abstractions should earn their place by removing real protocol
complexity or isolating a trust boundary.

## Why

The upstream SimpleX code that exists today is centered on:

- native Haskell client and agent libraries
- local CLI, Node addon, and native app integrations
- native app storage and transport assumptions

That means a truthful browser-native client needs new work in:

- browser-safe transport adaptation
- browser-safe durable state
- browser-safe key handling
- contact establishment and queue lifecycle in a browser runtime

The first protocol-core batch now exists in `src/browser-smp-core.mjs`, but a
browser still cannot behave exactly like the native Haskell transport against
today's raw SMP TCP/TLS endpoint. Browser JavaScript cannot open raw TCP sockets,
read the server certificate bytes needed for SimpleX server-identity pinning, or
read RFC5929 `tls-unique` channel binding. A production direct-browser transport
therefore needs a browser-compatible SMP server transport profile, such as a
WebSocket/WebTransport profile with an explicit replacement for those security
checks. That replacement must carry only encrypted SMP protocol blocks, never
chat plaintext.

The repo now ships these browser-owned layers without introducing a plaintext
server bridge:

- the browser shell and integration boundary
- browser-local chat continuity that does not require the server to retain plaintext history
- Haskell-owned local chat state
- executable SMP protocol primitives in the browser runtime
- a host contract that proves Haskell/browser interop is workable before transport is attempted
- a transport API that refuses sends unless a browser-native adapter is explicitly registered
- durable queue/contact/ratchet storage
- double-ratchet message packets
- contact request/accept lifecycle, file-transfer payloads, and retry scheduling
- first-party `window.SimplexWebTransport` adapter registration over the browser contact client
- XFTP-style encrypted file chunks
- an encrypted-chunk browser XFTP client and production XFTP server profile validation
- an upstream-style browser XFTP web transport, command profile, and encrypted file envelope assembly
- production browser SMP server profile validation
- per-queue SMP transport routing for native interop where the peer chooses a different reply relay

## Integration contract

The default UI expects a model shaped like:

```js
{
  loggedIn: true,
  hasSigner: true,
  error: "",
  sending: false,
  draftText: "",
  service: {
    transport_status: "connected",
    transport_error: ""
  },
  messages: [
    {
      direction: "incoming" | "outgoing",
      text: "hello",
      message_kind: "text" | "file",
      message_ref: "local-or-received-message-ref",
      sender_message_ref: "sender-local-ref-for-read-receipts",
      delivery_status: "sent",
      created_at: "2026-05-01T00:00:00Z",
      attachment: {
        name: "notes.txt",
        mime: "text/plain",
        size: 123
      }
    }
  ],
  uploads: [
    {
      upload_id: "upl-1",
      name: "notes.txt",
      status: "uploading",
      progress: 50
    }
  ],
  admin: false,
  adminMappings: []
}
```

The mount helper emits callbacks instead of owning transport:

- `onLogin()`
- `onSend(text)`
- `onDraftChange(text)`
- `onFilesSelected(files)`
- `onAdminRefresh()`
- `onAdminDeactivate(npub)`
- `onAdminDelete(npub)`

The transport facade exposed by `src/transport.js` is separate from the UI:

- `window.SimplexWebTransport.getStatus()`
- `window.SimplexWebTransport.connect(params)`
- `window.SimplexWebTransport.sendText({ contact_id, text, client_message_id })`
- `window.SimplexWebTransport.sendFiles({ contact_id, files, client_message_id })`
- `window.SimplexWebTransport.sendReadReceipt({ contact_id, message_ref })`
- `window.SimplexWebTransport.getMessages({ contact_id, limit })`
- `window.SimplexWebTransport.getMessageStatus({ contact_id, message_ref })`
- `window.SimplexWebTransport.deleteContact({ contact_id })`
- `window.SimplexWebTransport.disconnect()`
- `window.SimplexWebTransport.registerBrowserTransport(adapter)`

Without an adapter, `sendText` and `deleteContact` reject with
`SIMPLEX_WEB_TRANSPORT_UNAVAILABLE`.
This is the expected secure behavior; it keeps host sites from accidentally
routing plaintext through a server bridge while still giving them a stable
browser API to call. `src/browser-simplex-web-transport-adapter.mjs` supplies
the first-party adapter for real browser-native use: it connects the SMP
WebSocket profile, durable store, contact client, and optional XFTP web file
client, then registers that object with the facade.

## Browser SMP core

The `src/browser-smp-core.mjs` module is plain ESM so it can run in modern
browsers and Node tests without a bundler. Its public functions are deliberately
low-level:

- `parseSmpQueueUri()` and `formatSmpQueueUri()` handle `smp://` queue links.
- `encodeCommand()` and `parseCommand()` cover SMP client commands.
- `encodeBrokerMessage()` and `parseBrokerMessage()` cover SMP server responses and notifications.
- `encodeSignedTransmission()` and `parseSignedTransmission()` preserve the exact signed byte region.
- `encodeTransportBlock()` and `decodeTransportBlock()` implement fixed-size SMP blocks and v4 batches.
- `generateEd25519KeyPair()`, `generateX25519KeyPair()`, `ed25519Sign()`, `ed25519Verify()`, `x25519SharedSecret()`, `encryptSecretBox()`, and `encryptAesGcm()` provide browser-safe crypto building blocks.

`tests/vectors/simplex-web-interop-v1.json` stores deterministic local wire
fixtures for representative SMP commands, broker messages, handshakes, signed
transmissions, transport-block prefixes, agent envelopes, and XFTP chunks.
`tests/interop-vectors.test.mjs` checks both directions: current encoders must
still produce the committed vectors, and committed vectors must still parse and
verify. These are drift-detection fixtures for this implementation; they are not
yet upstream-certified SimpleX interoperability vectors.

This layer is not a chat UX adapter by itself. The contact client and store own
durable contacts, ratchets, retries, and browser storage.

## Browser Agent Helpers

The `src/browser-simplex-agent.mjs` module starts the layer above raw SMP:

- `encodePublicHeader()` and `parsePublicHeader()` implement the SimpleX client-message public header.
- `encodePrivateHeader()` and `parsePrivateHeader()` implement empty and confirmation private headers.
- `encryptClientMessage()` and `decryptClientMessageEnvelope()` wrap and unwrap encrypted client-message envelopes.
- `encryptRcvMessageBody()` and `decryptRcvMessageBody()` handle server-to-recipient message body encryption around timestamp, flags, and client envelope bytes.
- `prepareNewQueueRequest()` signs a browser-generated `NEW` command.
- `completeNewQueueRequest()` converts an `IDS` response into browser queue state with the derived server DH secret.
- `prepareRecipientCommand()` signs queue-scoped recipient commands such as `SUB` and `ACK`.
- `prepareInitialSenderMessage()` prepares the initial unsigned SMP `SEND` that carries the sender signing key in the encrypted confirmation body.

These helpers are deliberately transport-agnostic. They prepare protocol state
and signed transmissions; they do not open sockets or call any command API.

## Browser Client Orchestrator

The `src/browser-simplex-client.mjs` module turns primitives into queue-level
flows while remaining transport-agnostic:

- `createBrowserSimplexClient({ transport })` accepts any transport with `sendSignedTransmissions()` and `receiveSignedTransmissions()`.
- `createQueue()` sends signed `NEW`, waits for matching `IDS`, derives queue state, and remembers the queue under an optional label.
- `subscribeQueue()`, `acknowledgeMessage()`, `secureQueue()`, and `deleteQueue()` sign queue-scoped recipient commands.
- `sendInitialConfirmation()` sends the unsigned initial sender `SEND` and requires an `OK` response.
- `prepareInitialConfirmation()`, `sendPreparedInitialConfirmation()`, and
  `sendPreparedTransmission()` let higher layers persist and retry an already
  encrypted initial contact request without storing profile plaintext.
- `sendQueueMessage()` sends encrypted payload bytes through a sender queue and requires an `OK` response.
- broker `ERR` responses and unmatched correlation IDs fail closed before state is treated as successful.

The orchestrator still does not own UI or socket construction. Durable state,
retry scheduling, profile semantics, and ratchet persistence live in the browser
store, scheduler, server-profile, ratchet, and contact-client modules.

## Browser Store, Ratchet, Contact, And Retry

- `src/browser-simplex-store.mjs` serializes binary fields with tagged
  base64url JSON records, rejects hostile storage keys before writes, caps
  visible lists, recovers from poisoned list metadata, and scans storage keys
  for privacy-sensitive cleanup.
- `src/browser-simplex-ratchet.mjs` implements root-key derivation,
  sending/receiving chains, DH ratchet steps, skipped-message keys, and AES-GCM
  packet encryption.
- `src/browser-simplex-contact-client.mjs` creates invitations, activates
  contacts, sends encrypted contact requests from invitation URIs, verifies and
  accepts incoming contact requests, creates requester reply queues, sends and
  receives encrypted accept confirmations, persists ratchets, stores failed
  contact requests and failed accept confirmations as encrypted
  initial-confirmation retry tasks, sends active-contact messages only after
  outbound queue state is present, decrypts inbound queue messages, acknowledges
  received SMP messages, stores non-plaintext ACK retry tasks if ACK transport
  fails after decrypting contact requests, active messages, or accept
  confirmations, stores
  metadata-only received-message fingerprints to suppress duplicate redelivery
  without replaying the ratchet, validates higher-level payloads before
  persisting ratchet advances, uploads encrypted XFTP file chunks,
  ratchet-sends file descriptors and root keys,
  downloads received encrypted files, stores failed
  sends as already-ratcheted binary packet retry tasks instead of chat plaintext, and
  can send remote SMP `DEL` for browser-owned inbox queues before scrubbing
  queue, ratchet, received-message fingerprint, and retry records when a contact
  is deleted.
- `src/browser-simplex-scheduler.mjs` gives retryable work bounded exponential
  backoff with deterministic tests.

## Browser XFTP Core

`src/browser-xftp-core.mjs` chunks file bytes, encrypts every chunk with a
per-file root key, records plaintext and ciphertext hashes, and verifies all
chunks before reassembly.

`src/browser-xftp-client.mjs` sequences upload, download, and deletion through an
abstract encrypted-chunk server boundary. The server receives manifest metadata,
ciphertext, tags, and ciphertext hashes; it does not receive plaintext file
bytes or the file root key. The root key and manifest are expected to move
through the ratcheted chat layer, not through XFTP storage.

`src/browser-xftp-http-transport.mjs` implements that encrypted-chunk server
boundary over browser `fetch`: `POST /chunks`, `GET /chunks/:fileId/:index`, and
`DELETE /chunks/:fileId/:index`. Production URLs must be HTTPS; explicit
loopback HTTP is only allowed for local tests. The loopback test starts a real
HTTP server and verifies that uploaded request bodies contain ciphertext/tag
fields rather than plaintext file bytes.

`src/browser-xftp-server-profile.mjs` validates that a production browser XFTP
server endpoint uses a browser-safe `https://`, `wss://`, or WebTransport-style
profile, lists allowed origins, requires encrypted chunks, and keeps retention
bounded. This is a browser profile for encrypted XFTP storage, not direct raw
TCP/TLS access to existing native XFTP servers.

`src/browser-xftp-web-client.mjs` is the upstream-style browser XFTP web client
profile. It sends binary blocks with `fetch`, starts with a padded web hello and
32-byte challenge, verifies the server identity proof against the configured key
hash, sends a padded client handshake, and then moves one padded XFTP command
block per request. It now covers `PING` plus authenticated `FNEW`, `FPUT`,
`FGET`, and `FDEL` command wrappers. Above that command layer it encrypts the
upstream-style file envelope, pads to deterministic XFTP chunk sizes, serializes
recipient/sender file descriptions into a strict text form, uploads encrypted
chunks, downloads and verifies every encrypted chunk, decrypts the file
envelope, and deletes uploaded chunks from sender descriptions. Description
parsing enforces the party, bounded replica counts, contiguous chunk numbers and
offsets, total encrypted size, and connected-server match before a recipient or
sender key can be used in a network command. `FGET` download bodies are
decrypted as transport-encrypted XSalsa20-Poly1305 chunks and checked against
the expected SHA-256 chunk digest before the encrypted file chunk is returned.
The local loopback test exercises those commands through a real HTTP server;
live non-loopback coverage is gated through
`tests/live-interop.test.mjs`.

## Browser SMP Server Profile

`src/browser-smp-server-profile.mjs` validates browser SMP server profiles. A
production profile must use `wss://` or `https://`, list allowed origins, require
binary frames, keep 16 KiB SMP padding, carry a server identity hash, and define
a reviewed session-binding replacement.

## Browser WebSocket Transport

The `src/browser-smp-websocket-transport.mjs` module is the first browser
network transport profile:

- `normalizeSmpWebSocketUrl()` requires `ws://` or `wss://`, and rejects remote plaintext `ws://` by default.
- `connectBrowserSmpWebSocketTransport()` opens a browser WebSocket, receives a padded server handshake block, chooses a compatible SMP version, and sends the padded client handshake.
- `sendSignedTransmissions()` sends one fixed-size binary SMP transport block.
- `receiveSignedTransmissions()` reads one fixed-size binary SMP transport block and parses the signed transmissions.
- non-binary frames, short frames, long frames, bad sessions, and timeouts fail closed.

`tests/browser-smp-websocket-live.test.mjs` also starts a real local WebSocket
upgrade server and uses Node's browser-compatible `WebSocket` implementation to
exercise the transport without the fake socket harness. This verifies actual
client masking, server binary frames, handshake negotiation, block send, and
broker response receive on loopback. It is still not a production
browser-profile SMP server interoperability result.

`tests/live-interop.test.mjs` is the non-loopback contract. It is skipped unless
`SIMPLEX_WEB_LIVE_ENABLE=1` and reviewed endpoint variables are present. When
enabled, it checks a real browser-profile SMP WebSocket handshake plus PING/PONG
and a real upstream-style XFTP web HTTPS handshake, identity proof, and
PING/PONG. With `SIMPLEX_WEB_LIVE_XFTP_DESTRUCTIVE=1`, it also creates,
uploads, downloads, decrypts, verifies, and deletes one disposable XFTP chunk.
See `docs/LIVE_INTEROP.md`.

This profile is browser-native protocol transport, but it is not a claim that
ordinary browser JavaScript can speak the upstream raw TCP/TLS transport. Browser
JavaScript still cannot read TLS channel-binding data or perform the same server
certificate pinning as native simplexmq. Compatible servers need to expose an
explicit WebSocket/WebTransport profile whose security properties are reviewed
as part of the protocol, not as a website plaintext bridge.

## Next protocol steps

1. Extend the live browser matrix beyond Firefox and keep scrubbed run metadata
   outside the repo unless it is release evidence.
2. Add live Owl-to-browser receive coverage for native text, read receipts, and
   native file attachments against a compatible XFTP server.
3. Point the live SMP/XFTP harness at reviewed browser-profile servers and keep
   the passing run metadata outside the repo unless it is scrubbed release
   evidence.
4. Run the destructive live XFTP web harness against a reviewed disposable
   endpoint and preserve scrubbed passing evidence outside the source tree.
5. Replace or augment the local deterministic vectors with upstream-certified SimpleX implementation vectors for every encoded protocol layer.
6. Review the browser-profile SMP/XFTP server specifications against upstream
   SimpleX security goals before describing any deployment as production
   interoperable.
