# simplex-web

`simplex-web` is a browser-hosted chat client shell and browser-native SimpleX protocol workbench for SimpleX-facing websites.

The current tree now includes the first handwritten browser-native SMP protocol core slice in `src/browser-smp-core.mjs` and the first SimpleX agent-envelope/queue lifecycle helpers in `src/browser-simplex-agent.mjs`. The core implements low-level SimpleX Messaging Protocol byte encodings, queue URI parsing, command/response codecs, signed transmissions, fixed-size transport blocks, v4 batching, handshakes, and browser-compatible cryptographic primitives. The agent helper layer implements client-message envelopes, confirmation headers, received-message body encryption, `NEW` queue request preparation, `IDS` queue completion, signed recipient commands, and initial unsigned sender confirmation messages. The complete contact state machine, XFTP, and a production browser network transport are still being built.

`simplex-web` was made by AI and was adversarially tested as much as conceivably possible by Codex Desktop with ChatGPT 5.5 in the local environment described in `docs/SECURITY_REVIEW.md`.

Current scope:
- Ships a plain-JavaScript default chat UI that can be embedded into a hosted site.
- Ships a plain-JavaScript browser session store so hosted sites can preserve a chat thread locally without pushing plaintext history back into a server database.
- Ships a closed-by-default browser transport API boundary at `window.SimplexWebTransport`, so host sites can call a stable API without silently falling back to a plaintext website bridge.
- Ships `src/browser-smp-core.mjs`, a handwritten browser-native SMP protocol primitive layer with executable tests for binary encodings, queue URIs, command codecs, signed transmissions, transport blocks, handshakes, and Ed25519/X25519/XSalsa20-Poly1305/AES-GCM/SHA-256 helpers.
- Ships `src/browser-simplex-agent.mjs`, the first browser-native agent helper layer for SimpleX client-message envelopes, queue creation state, queue-scoped recipient commands, and initial sender confirmation messages.
- Ships `src/simplex-chat-websocket-adapter.js`, an adapter for a browser-reachable official SimpleX Chat WebSocket command API, intended for loopback/local SimpleX first.
- Includes a minimal Haskell-to-wasm reactor smoke test so browser-targeted Haskell can be validated honestly instead of hand-waved.
- Includes a Haskell-owned browser chat-state core with JS-string exports and a browser demo mounted on the default Secure Chat UI.
- Uses the Secure Chat interface from `nostr-blog` as the default/example presentation layer.
- Keeps the browser surface framework-free so it can be mounted in existing sites without a build step.
- Includes Wizardry-style runtime tests for the UI, adapter, file bridge, and adversarial escaping contracts.

Not shipped yet:
- The full SimpleX agent/contact protocol on top of SMP queues.
- XFTP.
- Double-ratchet message state integrated into browser storage.
- Direct JavaScript transport to existing raw TCP/TLS SMP/XFTP servers. Browsers do not expose raw TCP sockets, server certificate bytes for SimpleX server-identity pinning, or RFC5929 `tls-unique` channel binding to JavaScript, so a production browser transport needs a browser-compatible SMP server transport profile rather than a pretend downgrade.
- Haskell/WASM build output.

The browser SMP core is intentionally separate from the SimpleX Chat WebSocket adapter. The adapter is useful for local daemon-backed testing, but it sees plaintext inside the local SimpleX Chat API. The SMP core is the path toward a browser client that constructs and encrypts protocol transmissions itself.

## Layout

- `src/default-chat.js`: default/example chat renderer and DOM mount helper.
- `src/default-chat.css`: default/example chat styles extracted from the current `nostr-blog` contact chat.
- `src/session-store.js`: bounded browser-local persistence helpers for per-user secure-chat session state.
- `src/browser-smp-core.mjs`: browser-native SMP protocol primitives and crypto helpers.
- `src/browser-simplex-agent.mjs`: browser-native SimpleX agent envelope and queue lifecycle helpers.
- `src/transport.js`: browser transport facade that fails closed until a real browser-native adapter is registered.
- `src/simplex-chat-websocket-adapter.js`: transport adapter that registers with the facade and sends text/files through a browser-reachable SimpleX Chat WebSocket command API.
- `scripts/simplex-web-file-bridge.mjs`: optional loopback file bridge for staging browser-selected files for a local SimpleX Chat API.
- `examples/mock-chat.html`: runnable browser example with a mocked chat state.
- `tests/default-chat.test.js`: Node unit tests for HTML contract, escaping, and status mapping.
- `tests/session-store.test.js`: Node unit tests for bounded local persistence and key normalization.
- `tests/transport.test.js`: Node unit tests for the closed transport contract and adapter normalization.
- `tests/browser-smp-core.test.mjs`: Node unit and fuzz tests for the handwritten SMP protocol core.
- `tests/browser-simplex-agent.test.mjs`: Node unit and fuzz tests for browser-native agent envelopes and queue lifecycle helpers.
- `tests/simplex-chat-websocket-adapter.test.js`: Node unit tests for the SimpleX Chat WebSocket adapter.
- `tests/file-bridge.test.mjs`: Node integration tests for file bridge origin, path, symlink, size, and output-shape boundaries.
- `tests/simplex-live-e2e.test.mjs`: optional two-daemon live SimpleX E2E test for the WebSocket adapter, using temporary profiles.
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

## Run

```sh
npm test
```

Optional Haskell/WASM checks require `wasm32-wasi-ghc`:

```sh
./tests-simplex-web-runtime.sh
./tests-haskell-wasm-runtime.sh
./tests-haskell-core-runtime.sh
```

The current smoke reactor host contract is:

- instantiate the module with `wasi_snapshot_preview1`
- call `wasi.initialize(instance)`
- call `instance.exports.hs_init(0, 0)`
- then call exported functions like `smoke_add` or `smoke_fib`

The current Haskell chat core host contract is the same, with one extra step:

- run `post-link.mjs` on the compiled wasm file when JSFFI types like `JSString` are used
- treat the generated glue file as an ES module (the current wrapper writes `build/haskell-core/core.mjs`)
- instantiate with both `ghc_wasm_jsffi` and `wasi_snapshot_preview1`
- call `wasi.initialize(instance)`
- call `instance.exports.hs_init(0, 0)`
- then call exported functions like `core_snapshot_json`, `core_send_text`, or `core_receive_text`

## Browser transport API

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

An adapter registers itself with:

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

This repo still does not ship the actual SimpleX SMP/XFTP protocol transport. The API exists to keep integration code stable while preserving secure failure when no browser-native transport is present.

## Browser SMP core

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

This is protocol-core code, not yet a complete chat agent. It does not create contacts, manage ratchets, persist queue state, receive loops, or send XFTP files yet.

The next agent layer can be imported separately:

```js
import {
  completeNewQueueRequest,
  decryptClientMessageEnvelope,
  prepareInitialSenderMessage,
  prepareNewQueueRequest,
  prepareRecipientCommand
} from "simplex-web/browser-simplex-agent";

const pending = prepareNewQueueRequest({
  sessionId,
  corrId,
  rcvSignSeed,
  rcvDhSeed
});
// Send pending.transmission through a browser SMP transport, then process IDS:
const queue = completeNewQueueRequest(pending, idsBrokerMessage);
const sub = prepareRecipientCommand(queue, {
  sessionId,
  corrId: new TextEncoder().encode("sub-1"),
  command: { type: "SUB" }
});
```

This helper layer is still transport-agnostic. It prepares and parses protocol state; it does not open sockets by itself.

## SimpleX Chat WebSocket adapter

Load the facade first, then the adapter:

```html
<script src="/static/simplex-web-transport.js"></script>
<script>
window.SimplexWebSocketAdapterConfig = {
  url: "ws://127.0.0.1:5225",
  user_id: "1"
};
</script>
<script src="/static/simplex-chat-websocket-adapter.js"></script>
```

The adapter sends text with the official SimpleX Chat command WebSocket flow, using JSON composed messages so message bodies cannot be interpreted as follow-up CLI commands:

```text
/_user <user_id>
/_send @<contact_id> json [{"msgContent":{"type":"text","text":"message"},"mentions":{}}]
```

File sends use SimpleX's `ComposedMessage` file-transfer command shape rather than embedding file bytes inside chat text:

```text
/_send @<contact_id> json [{"fileSource":{"filePath":"/local/path/to/file"},"msgContent":{"type":"file","text":"optional caption"},"mentions":{}}]
```

Browsers do not expose selected files' absolute local paths to web pages. For ordinary browser `File` objects, configure a loopback-only `fileBridgeUrl` that stages the selected file on the same machine as the SimpleX Chat WebSocket API and returns an absolute local `filePath`. Without a local file path or loopback file bridge, attachment sending fails closed.

The default chat renderer only autoloads attachment URLs from `data:`, `blob:`, or loopback `http(s)` URLs. Remote and relative attachment URLs render as inert download labels so imported metadata cannot force the browser to beacon to arbitrary hosts.

The optional file bridge is origin-restricted by default, resolves symlinks before reads, and sends `X-Content-Type-Options: nosniff`. Set `SIMPLEX_WEB_FILE_BRIDGE_ORIGIN` to the exact site origin that should be allowed to stage and read files, for example:

```sh
SIMPLEX_WEB_FILE_BRIDGE_ORIGIN=https://example.com npm run file-bridge
```

Use `SIMPLEX_WEB_FILE_BRIDGE_ORIGIN='*'` only for local throwaway testing; it lets any website that can reach loopback read allowed bridge responses.

Remote WebSocket endpoints are rejected by default because they can see plaintext. To use one deliberately, pass `allowRemote: true` and only point it at a trusted SimpleX Chat API endpoint, not a website bridge.

## Release hygiene

The repository intentionally does not track generated outputs such as `build/`, `node_modules/`, coverage output, logs, or packed `.tgz` files. A push-ready 1.0 tree should have `git status --short --branch` clean after running:

```sh
npm test
npm run test:browser
npm run test:live
npm run test:haskell
npm audit --audit-level=moderate
npm pack --dry-run --json
```

`npm run test:live` requires a `simplex-chat` binary. It uses `~/.local/bin/simplex-chat` when present, or `SIMPLEX_CHAT_BIN=/path/to/simplex-chat`.

`npm run test:haskell` requires `wasm32-wasi-ghc`; source the `ghc-wasm-meta` env first when it is installed outside the default shell path.

## License

`simplex-web` is licensed under the GNU Affero General Public License version 3 only (`AGPL-3.0-only`). See `LICENSE`.

SimpleX, SimpleX Chat, and related marks belong to their respective owners. This project is independent of SimpleX while implementing the same protocol.
