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
5. `src/transport.js` is the public browser API. It is unavailable until an
   adapter is registered, so host pages cannot accidentally send plaintext
   through a server fallback.
6. `src/simplex-chat-websocket-adapter.js` is the current daemon-backed adapter. It talks
   to a browser-reachable SimpleX Chat command WebSocket, preferably loopback.
7. `scripts/simplex-web-file-bridge.mjs` is an optional loopback helper that
   stages browser `File` objects on disk for SimpleX file-send commands.
8. `haskell/src/Simplex/Web/*.hs` proves the Haskell-to-browser boundary with a
   small state core and a smoke module; it is not yet the network protocol core.

The shape is intentionally conservative: the UI can be embedded on any page, the
transport boundary fails closed, and the code can be tested in Node, browsers,
Safari automation, live SimpleX daemons, and wasm GHC without a bundler.

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
- a closed-by-default `window.SimplexWebTransport` facade for host-site integration
- a SimpleX Chat WebSocket adapter that can send through a browser-reachable SimpleX Chat command API

It does **not** yet own the complete SimpleX browser client:

- no full agent/contact state machine yet
- no integrated double-ratchet message state yet
- no durable browser queue/contact store yet
- no XFTP yet
- no production direct browser transport to existing raw TCP/TLS SMP servers yet

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
- local CLI / Node addon / WebSocket daemon integrations
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

Until the remaining layers exist, the safest thing this repo can ship honestly is:

- the browser shell and integration boundary
- browser-local chat continuity that does not require the server to retain plaintext history
- Haskell-owned local chat state
- executable SMP protocol primitives in the browser runtime
- a host contract that proves Haskell/browser interop is workable before transport is attempted
- a transport API that refuses sends unless a browser-native adapter is explicitly registered
- a loopback-first adapter for the official SimpleX Chat command WebSocket, avoiding plaintext website relay when users provide a local/browser-reachable SimpleX endpoint

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
- `window.SimplexWebTransport.disconnect()`
- `window.SimplexWebTransport.registerBrowserTransport(adapter)`

Without an adapter, `sendText` rejects with `SIMPLEX_WEB_TRANSPORT_UNAVAILABLE`. This is the expected secure behavior; it keeps host sites from accidentally routing plaintext through a server bridge while still giving them a stable browser API to call.

`src/simplex-chat-websocket-adapter.js` provides the first real adapter. It registers via `registerBrowserTransport` and sends text through a SimpleX Chat command WebSocket:

- activate the configured SimpleX user with `/_user <user_id>`
- send to the configured contact with `/_send @<contact_id> json [...]`, including text sends, so message bodies remain structured content rather than command text
- normalize the SimpleX `newChatItems` response back into the facade receipt

The adapter only accepts loopback endpoints by default. Remote endpoints require `allowRemote: true` because they can see plaintext before SimpleX encrypts and sends through its own network transport.

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

This layer is not a chat UX adapter by itself. The next layer has to own durable
queues, contacts, ratchets, retries, receive loops, and browser storage.

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
and signed transmissions; they do not open sockets or call the daemon adapter.

## Next protocol steps

1. Add a browser agent state machine for queue creation, contact confirmation, queue securing, send, subscribe, receive, acknowledge, suspend, and delete.
2. Add browser durable storage for keys, queue state, ratchet state, pending messages, and skipped-message keys.
3. Port or reimplement the SimpleX agent message envelope and double-ratchet flow on top of the SMP core.
4. Define and test a browser-compatible SMP server transport profile that preserves SimpleX server identity and session binding without exposing plaintext.
5. Add XFTP protocol primitives and browser-safe file transfer state.
6. Keep the SimpleX Chat WebSocket adapter compatible for local daemon-backed comparison tests, but do not use it as the browser-native transport.
