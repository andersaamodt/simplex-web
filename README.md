# simplex-web

`simplex-web` is a browser-side toolkit for putting SimpleX-style private chat
inside a website without sending chat plaintext through the website's server.

The goal is simple: a site should be able to mount a chat panel, keep local chat
state in the visitor's browser, create SimpleX queues and contacts, encrypt
messages and files in the browser, and talk to browser-compatible SimpleX relay
profiles using ordinary web APIs such as WebSocket and `fetch`.

This repository exists because the normal upstream SimpleX stack is built around
native clients, native Haskell libraries, and raw TCP/TLS transports. Ordinary
browser JavaScript cannot open raw TCP sockets or inspect the TLS channel-binding
data that native SimpleX clients use. `simplex-web` therefore implements the
browser-facing pieces directly and refuses to fall back to a website/server
bridge that would see plaintext.

In practical website terms, `simplex-web` gives you three layers:

- A framework-free Secure Chat UI and local browser session store.
- Browser-native SimpleX protocol building blocks: SMP queue commands, signed
  transmissions, encrypted agent envelopes, contact setup, ratchets, retries,
  and encrypted XFTP-style file chunks.
- Browser transport profiles for compatible servers: SMP over binary WebSocket
  blocks and upstream-style XFTP web blocks over HTTPS/`fetch`.

It is independent of SimpleX while implementing the same protocol concepts.
SimpleX, SimpleX Chat, and related marks belong to their respective owners.

## Status

This is the real browser-native `simplex-web` codebase, not the old placeholder
bridge:

- No SimpleX Chat command API adapter is shipped.
- No loopback file bridge is shipped.
- No mock chat transport is shipped.
- No plaintext website/server bridge is shipped.
- The default public transport facade fails closed until a browser-native
  adapter is registered.

What works locally today:

- Browser-native SMP encoding, signing, transport blocks, handshakes, and queue
  command helpers.
- Browser contact creation, invitation URI creation, encrypted contact requests,
  queue securing, ACKs, active contact messaging, retry scheduling, and durable
  browser state.
- Browser-owned double-ratchet message encryption.
- Encrypted XFTP-style file chunking, upload/download sequencing, verified
  reassembly, and an HTTPS/`fetch` encrypted chunk transport.
- Upstream-style XFTP web hello, identity-proof verification, padded handshake,
  binary command blocks, PING, authenticated file-command wrappers, and
  transport-encrypted download chunk verification.
- Binary SMP-over-WebSocket transport for browser-compatible SMP servers.
- Local deterministic wire-format vectors, loopback WebSocket/fetch transport
  tests, skipped-by-default live interop tests, fuzz/property tests, browser
  rendering tests, and Haskell/WASM smoke checks.

What is still required before claiming full production SimpleX browser-client
interoperability:

- Reviewed non-loopback browser-profile SMP and XFTP servers.
- Passing live compatibility runs against those servers.
- Upstream-certified SimpleX protocol vectors for every encoded layer.
- A security review outside this Codex Desktop environment.

The current tree includes a handwritten browser-native SMP protocol core in
`src/browser-smp-core.mjs`, SimpleX agent-envelope/queue lifecycle helpers in
`src/browser-simplex-agent.mjs`, a queue-level client orchestrator in
`src/browser-simplex-client.mjs`, durable browser state in
`src/browser-simplex-store.mjs`, browser-owned double-ratchet state in
`src/browser-simplex-ratchet.mjs`, a contact client in
`src/browser-simplex-contact-client.mjs`, retry scheduling in
`src/browser-simplex-scheduler.mjs`, XFTP chunk/manifest helpers in
`src/browser-xftp-core.mjs`, an encrypted-chunk XFTP client in
`src/browser-xftp-client.mjs`, an HTTPS/fetch encrypted-chunk transport in
`src/browser-xftp-http-transport.mjs`, an upstream-style XFTP web client in
`src/browser-xftp-web-client.mjs`, reviewed browser SMP/XFTP server profile
validation in `src/browser-smp-server-profile.mjs` and
`src/browser-xftp-server-profile.mjs`, and a binary SMP-over-WebSocket browser
transport profile in `src/browser-smp-websocket-transport.mjs`.

`simplex-web` was made by AI and was adversarially tested as much as
conceivably possible by Codex Desktop with ChatGPT 5.5 in the local environment
described in `docs/SECURITY_REVIEW.md`.

## How It Fits Into A Website

A website can use `simplex-web` in the same way it would use any other
front-end library:

1. Mount the default chat UI, or build its own UI on top of the lower-level
   modules.
2. Store drafts, recent messages, contacts, queues, ratchets, and pending work
   in browser-local storage.
3. Register a real browser-native transport adapter with
   `window.SimplexWebTransport`.
4. Use browser-compatible SMP/XFTP server profiles for relay and file storage.

The important boundary is that the website server should serve static assets and
application pages. It should not receive chat plaintext, file plaintext, or file
root keys. Messages are encrypted before they leave the browser. XFTP storage
receives encrypted chunks only; the file root key is delivered through the
ratcheted chat layer.

## Current Scope

- Ships a plain-JavaScript default chat UI that can be embedded into a hosted site.
- Ships a plain-JavaScript browser session store so hosted sites can preserve a chat thread locally without pushing plaintext history back into a server database.
- Ships a closed-by-default browser transport API boundary at `window.SimplexWebTransport`, so host sites can call a stable API without silently falling back to a plaintext website bridge.
- Ships browser-native SMP protocol primitives for binary encodings, queue URIs, command codecs, signed transmissions, transport blocks, handshakes, and browser-compatible cryptographic helpers.
- Ships browser-native agent helpers for SimpleX client-message envelopes, queue creation state, queue-scoped recipient commands, and initial sender confirmation messages.
- Ships a low-level queue client orchestrator over an abstract SMP transport.
- Ships durable browser queue/contact/ratchet/pending-task storage.
- Ships browser-owned double-ratchet encryption with skipped-message-key handling.
- Ships a contact lifecycle client that creates invitation URIs, sends and accepts encrypted contact requests, persists contacts, sends and receives ratcheted messages and XFTP file descriptors, acknowledges received queue messages, downloads received encrypted files, and queues failed sends for retry.
- Ships bounded retry scheduling for offline/transient transport failure.
- Ships XFTP-style encrypted chunk manifests, an encrypted-chunk upload/download client, tamper detection, and download assembly.
- Ships a browser XFTP-over-HTTPS/fetch transport for encrypted chunk upload, download, and deletion.
- Ships an upstream-style browser XFTP web client for binary HTTPS/fetch hello, identity proof verification, padded handshake, PING, authenticated FNEW/FPUT/FGET/FDEL command wrappers, and transport-encrypted FGET body decryption.
- Ships production browser SMP server profile validation for binary frames, origin policy, padding, and session-binding requirements.
- Ships production browser XFTP server profile validation for encrypted chunk storage endpoints.
- Ships a binary SMP-over-WebSocket transport profile for browser-reachable SMP servers that expose one padded SMP block per WebSocket frame.
- Includes Haskell-to-wasm validation slices so browser-targeted Haskell can be tested honestly.
- Uses the Secure Chat interface from `nostr-blog` as the default/example presentation layer.
- Keeps the browser surface framework-free so it can be mounted in existing sites without a build step.

Not shipped:

- A SimpleX Chat command API adapter.
- A loopback file bridge.
- A mock chat transport.
- A plaintext website/server bridge.
- Direct JavaScript transport to existing raw TCP/TLS SMP/XFTP servers. Browsers do not expose raw TCP sockets, server certificate bytes for SimpleX server-identity pinning, or RFC5929 `tls-unique` channel binding to JavaScript, so a production browser transport needs a browser-compatible SMP server transport profile rather than a pretend downgrade.
- Checked-in Haskell/WASM build output.

## Layout

- `src/default-chat.js`: default/example chat renderer and DOM mount helper.
- `src/default-chat.css`: default/example chat styles extracted from the current `nostr-blog` contact chat.
- `src/session-store.js`: bounded browser-local persistence helpers for per-user secure-chat session state.
- `src/transport.js`: browser transport facade that fails closed until a browser-native adapter is registered.
- `src/browser-smp-core.mjs`: browser-native SMP protocol primitives and crypto helpers.
- `src/browser-simplex-agent.mjs`: browser-native SimpleX agent envelope and queue lifecycle helpers.
- `src/browser-simplex-client.mjs`: queue-level browser SimpleX client orchestrator over an abstract SMP transport.
- `src/browser-simplex-contact-client.mjs`: contact lifecycle, active contact sends, ratchet persistence, and retry enqueueing.
- `src/browser-simplex-ratchet.mjs`: browser-owned double-ratchet state and message encryption.
- `src/browser-simplex-scheduler.mjs`: bounded retry scheduling for pending browser work.
- `src/browser-simplex-store.mjs`: durable browser queue, contact, ratchet, and pending-task records.
- `src/browser-smp-server-profile.mjs`: production browser SMP server profile validation.
- `src/browser-smp-websocket-transport.mjs`: browser binary WebSocket transport profile for padded SMP blocks.
- `src/browser-xftp-core.mjs`: encrypted XFTP-style file chunking, manifests, and reassembly checks.
- `src/browser-xftp-client.mjs`: browser XFTP encrypted chunk upload/download sequencing over a reviewed server boundary.
- `src/browser-xftp-http-transport.mjs`: browser XFTP-over-HTTPS/fetch encrypted chunk transport.
- `src/browser-xftp-web-client.mjs`: upstream-style browser XFTP web handshake, identity proof, binary command transport, command wrappers, and transport chunk decryption.
- `src/browser-xftp-server-profile.mjs`: production browser XFTP server profile validation.
- `tests/default-chat.test.js`: Node unit tests for HTML contract, escaping, and status mapping.
- `tests/interop-vectors.test.mjs`: deterministic local interoperability-vector checks for SMP, agent envelopes, and XFTP chunks.
- `tests/vectors/simplex-web-interop-v1.json`: checked hex fixtures for local wire-format drift detection.
- `tests/session-store.test.js`: Node unit tests for bounded local persistence and key normalization.
- `tests/transport.test.js`: Node unit tests for the closed transport contract and adapter normalization.
- `tests/browser-smp-core.test.mjs`: Node unit and fuzz tests for the handwritten SMP protocol core.
- `tests/browser-simplex-agent.test.mjs`: Node unit and fuzz tests for browser-native agent envelopes and queue lifecycle helpers.
- `tests/browser-simplex-client.test.mjs`: Node tests for queue-level client orchestration and fail-closed response handling.
- `tests/browser-simplex-contact-client.test.mjs`: Node tests for contact state, ratcheted sends, and retry enqueueing.
- `tests/browser-simplex-e2e-broker.test.mjs`: in-process browser-profile SMP broker E2E for two clients, ratcheted messages, ACKs, and forged-signature rejection.
- `tests/browser-simplex-ratchet.test.mjs`: Node tests for double-ratchet send/receive, skipped messages, and tamper rejection.
- `tests/browser-simplex-scheduler.test.mjs`: Node tests for retry timing and completion.
- `tests/browser-simplex-store.test.mjs`: Node tests for durable store serialization and hostile keys.
- `tests/browser-smp-server-profile.test.mjs`: Node tests for browser SMP server profile downgrade rejection.
- `tests/browser-smp-websocket-transport.test.mjs`: Node tests for the binary browser WebSocket SMP transport profile.
- `tests/browser-smp-websocket-live.test.mjs`: Node loopback WebSocket server test for real browser transport framing, handshake, send, and receive.
- `tests/live-interop.test.mjs`: skipped-by-default live SMP/XFTP interoperability harness for reviewed non-loopback endpoints.
- `tests/browser-xftp-core.test.mjs`: Node tests for XFTP chunk encryption, manifest verification, and tamper rejection.
- `tests/browser-xftp-client.test.mjs`: Node tests for encrypted XFTP upload/download, deletion, and tamper rejection.
- `tests/browser-xftp-http-transport.test.mjs`: Node loopback HTTP/fetch test for encrypted XFTP chunk upload, download, and deletion.
- `tests/browser-xftp-web-client.test.mjs`: Node loopback HTTP/fetch tests for XFTP web identity proof, PING, authenticated file commands, transport chunk decryption, and tamper rejection.
- `tests/browser-xftp-server-profile.test.mjs`: Node tests for browser XFTP server profile downgrade rejection.
- `tests-simplex-web-runtime.sh`: Wizardry-style shell wrapper around the focused runtime checks.
- `haskell/src/Simplex/Web/Smoke.hs`: first Haskell/WASM smoke module exported as a reactor.
- `haskell/src/Simplex/Web/Core.hs`: first Haskell-owned chat-state core slice with browser-callable exports.
- `tests/haskell-smoke.test.cjs`: Node/WASI runtime checks for the compiled reactor exports.
- `tests-haskell-wasm-runtime.sh`: Wizardry-style shell wrapper that compiles the Haskell smoke module and executes the runtime checks.
- `tests/haskell-core.test.mjs`: Node/WASI runtime checks for the string-capable Haskell chat core.
- `tests-haskell-core-runtime.sh`: Wizardry-style shell wrapper that compiles the Haskell chat core, runs post-link JSFFI glue generation, and executes the runtime checks.
- `examples/haskell-smoke.html`: browser smoke page for the compiled Haskell reactor.
- `examples/haskell-core-chat.html`: browser example that mounts the default Secure Chat UI against the Haskell core.
- `docs/ARCHITECTURE.md`: current boundaries and next protocol steps.
- `docs/HASKELL_BROWSER_STATUS.md`: current Haskell/browser status and why the UI ships first.
- `docs/SECURITY_REVIEW.md`: adversarial review scope, findings, coverage, and release posture.
- `docs/LIVE_INTEROP.md`: live SMP/XFTP endpoint contract and environment variables.

## Run

```sh
npm test
```

Optional browser and Haskell/WASM checks:

```sh
npm run test:browser
npm run test:live
./tests-haskell-wasm-runtime.sh
./tests-haskell-core-runtime.sh
```

`npm run test:live` skips by default. Set the environment variables described
in `docs/LIVE_INTEROP.md` to run it against reviewed browser-profile SMP/XFTP
servers.

The Haskell/WASM checks require `wasm32-wasi-ghc`. Source the
`ghc-wasm-meta` environment first when it is installed outside the default shell
path.

## Browser Transport API

Load `src/transport.js` to expose `window.SimplexWebTransport`.

By default it is intentionally unavailable:

```js
window.SimplexWebTransport.getStatus();
// {
//   available: false,
//   transport_status: "browser-native-unavailable",
//   transport_error: "browser-native simplex-web transport is not available"
// }

await window.SimplexWebTransport.sendText({ contact_id: "contact-1", text: "hello" });
// rejects with code SIMPLEX_WEB_TRANSPORT_UNAVAILABLE
```

A browser-native adapter registers itself with:

```js
window.SimplexWebTransport.registerBrowserTransport({
  getStatus() {
    return { transport_status: "direct-browser-smp", transport_error: "" };
  },
  async connect(params) {
    // Initialize browser-native durable state, keys, contacts, and queues.
  },
  async sendText(message) {
    // Send without a plaintext server bridge.
    // message: { contact_id, text, client_message_id }
    return { message_ref: "browser-message-ref" };
  },
  async disconnect() {}
});
```

The facade keeps integration code stable while preserving secure failure when no
browser-native transport is present.

## Browser SMP Core

Import the protocol primitives as ESM:

```js
import {
  encodeSignedTransmission,
  encodeTransportBlock,
  generateEd25519KeyPair,
  parseSmpQueueUri
} from "simplex-web/browser-smp-core";

const queue = parseSmpQueueUri("smp://...");
const senderKey = generateEd25519KeyPair();
const tx = encodeSignedTransmission(4, sessionIdBytes, {
  privateKey: senderKey.secretKey,
  corrId: new TextEncoder().encode("corr-1"),
  queueId: queue.queueId,
  command: {
    type: "SEND",
    flags: { notification: false },
    body: encryptedMessageBytes
  }
});
const block = encodeTransportBlock(4, [tx]);
```

This is protocol-core code. The higher-level modules own contacts, ratchets,
durable state, retry scheduling, and XFTP-style file chunks.

The next agent layer can be imported separately:

```js
import {
  completeNewQueueRequest,
  prepareNewQueueRequest,
  prepareRecipientCommand
} from "simplex-web/browser-simplex-agent";

const pending = prepareNewQueueRequest({
  sessionId,
  corrId,
  rcvSignSeed,
  rcvDhSeed
});
const queue = completeNewQueueRequest(pending, idsBrokerMessage);
const sub = prepareRecipientCommand(queue, {
  sessionId,
  corrId: new TextEncoder().encode("sub-1"),
  command: { type: "SUB" }
});
```

The queue-level client orchestrator wires the helper layer to any compatible SMP
transport:

```js
import { createBrowserSimplexClient } from "simplex-web/browser-simplex-client";

const client = createBrowserSimplexClient({ transport: smpTransport });
const queue = await client.createQueue({ label: "inbox" });
await client.subscribeQueue("inbox");
await client.acknowledgeMessage(queue, msgIdBytes);
```

The browser WebSocket transport profile is the first network-facing browser
primitive:

```js
import { connectBrowserSmpWebSocketTransport } from "simplex-web/browser-smp-websocket-transport";

const smpTransport = await connectBrowserSmpWebSocketTransport({
  url: "wss://smp.example.net/smp",
  keyHash: expectedServerIdentityHashBytes
});

smpTransport.sendSignedTransmissions([sub]);
const incoming = await smpTransport.receiveSignedTransmissions({ kind: "broker" });
```

This transport only moves binary SMP blocks. It does not call the SimpleX Chat
command API. Because browser JavaScript cannot inspect raw TLS channel binding,
this module is explicitly a browser WebSocket profile for compatible SMP
servers, not a claim that existing raw TCP/TLS SMP servers can be reached
directly from ordinary browser JavaScript.

## Browser Contact Client

The contact client combines the queue client, durable store, retry scheduler,
and ratchet helpers:

```js
import { createBrowserSimplexContactClient } from "simplex-web/browser-simplex-contact-client";
import { createBrowserSimplexStore } from "simplex-web/browser-simplex-store";

const contacts = createBrowserSimplexContactClient({
  client,
  store: createBrowserSimplexStore({ namespace: "site-chat" })
});

const invitation = await contacts.createInvitation({ id: "alice", corrId: "new-1" });
const uri = contacts.invitationUri("alice");
await contacts.requestContact("bob", uri, { corrId: "req-1" });
await contacts.receiveContactRequest("alice", { keyCorrId: "key-1", ackCorrId: "ack-1" });
contacts.activateContact("alice", {
  rootKey,
  remoteDhPublicKey,
  outboundQueue
});
await contacts.sendText("alice", "hello");
```

Failed sends are persisted as retry tasks. Contact sends require active contact
state, a ratchet, and an outbound queue; otherwise they fail closed. File sends
first upload encrypted XFTP chunks, then ratchet-send the manifest and file root
key as a contact payload:

```js
const sent = await contacts.sendFile("alice", fileBytes, { name: "notes.txt" });
```

Inbound queue messages decrypt the server-wrapped received body, decrypt the
contact ratchet packet, persist the updated ratchet, and acknowledge the SMP
message:

```js
const received = await contacts.receiveNext("alice", { ackCorrId: "ack-1" });
if (received.file) {
  const fileBytes = await contacts.downloadReceivedFile(received);
}
```

Retryable failed sends can be drained explicitly:

```js
await contacts.drainDueRetries();
```

The E2E broker test exercises two browser clients through queue creation,
recipient `KEY`, signed `SEND`, encrypted server-wrapped `MSG`, ratchet
decryption, and `ACK`. It is still an in-process browser-profile harness, not a
claim of interoperability with existing raw TCP/TLS SimpleX servers.

## XFTP Core

```js
import { createXftpUpload, assembleXftpDownload } from "simplex-web/browser-xftp-core";
import { createBrowserXftpClient } from "simplex-web/browser-xftp-client";
import {
  connectBrowserXftpWebClient,
  downloadXftpWebFileChunk,
  pingXftpWeb
} from "simplex-web/browser-xftp-web-client";

const upload = createXftpUpload(fileBytes, { name: "notes.txt" });
const fileBytesAgain = assembleXftpDownload(upload.manifest, upload.chunks, upload.rootKey);

const client = createBrowserXftpClient({ server, profile });
const sent = await client.uploadFile(fileBytes, { name: "notes.txt" });
const received = await client.downloadFile(sent.manifest, sent.rootKey);

const xftpWeb = await connectBrowserXftpWebClient({
  url: "https://xftp.example.test/",
  keyHash
});
await pingXftpWeb(xftpWeb);
```

The older `browser-xftp-core` and `browser-xftp-client` modules are local
encrypted-chunk helpers used by the contact-file workbench and tests. They keep
plaintext file bytes and root keys on the browser/client side.

The newer `browser-xftp-web-client` module is the upstream-style browser XFTP
web transport: binary fetch requests, web challenge, server identity proof,
padded handshake, PING, authenticated file-command wrappers, and
transport-encrypted download chunk verification. That is the path to use for
real browser-profile XFTP server interoperability.

## Release Hygiene

The repository intentionally does not track generated outputs such as `build/`,
`node_modules/`, coverage output, logs, or packed `.tgz` files. A push-ready 1.0
tree should have `git status --short --branch` clean after running:

```sh
npm test
npm run test:browser
npm run test:haskell
npm audit --audit-level=moderate
npm pack --dry-run --json
```

## License

`simplex-web` is licensed under the GNU Affero General Public License version 3
only (`AGPL-3.0-only`). See `LICENSE`.

SimpleX, SimpleX Chat, and related marks belong to their respective owners.
This project is independent of SimpleX while implementing the same protocol.
