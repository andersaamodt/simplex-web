# simplex-web

`simplex-web` is an experimental browser-hosted chat client shell for SimpleX.

Current scope:
- Ships a plain-JavaScript default chat UI that can be embedded into a hosted site.
- Ships a plain-JavaScript browser session store so hosted sites can preserve a chat thread locally without pushing plaintext history back into a server database.
- Ships a closed-by-default browser transport API boundary at `window.SimplexWebTransport`, so host sites can call a stable API without silently falling back to a plaintext server bridge.
- Includes a minimal Haskell-to-wasm reactor smoke test so browser-targeted Haskell can be validated honestly instead of hand-waved.
- Includes a Haskell-owned browser chat-state core with JS-string exports and a browser demo mounted on the default Secure Chat UI.
- Uses the Secure Chat interface from `nostr-blog` as the default/example presentation layer.
- Keeps the browser surface framework-free so it can be mounted in existing sites without a build step.
- Includes Wizardry-style runtime tests for the UI contract and adversarial escaping.

Not shipped yet:
- A true browser-native SimpleX protocol core.
- Haskell/WASM build output.
- Direct browser transport to SMP/XFTP servers.

The reason the protocol core is not here yet is architectural, not branding: the existing upstream SimpleX codebase is native Haskell plus daemon/API integrations, and this repo is the shell around the browser-facing surface while that deeper transport/core work remains experimental.

## Layout

- `src/default-chat.js`: default/example chat renderer and DOM mount helper.
- `src/default-chat.css`: default/example chat styles extracted from the current `nostr-blog` contact chat.
- `src/session-store.js`: bounded browser-local persistence helpers for per-user secure-chat session state.
- `src/transport.js`: browser transport facade that fails closed until a real browser-native adapter is registered.
- `examples/mock-chat.html`: runnable browser example with a mocked chat state.
- `tests/default-chat.test.js`: Node unit tests for HTML contract, escaping, and status mapping.
- `tests/session-store.test.js`: Node unit tests for bounded local persistence and key normalization.
- `tests/transport.test.js`: Node unit tests for the closed transport contract and adapter normalization.
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

## Run

```sh
node --test tests/default-chat.test.js
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

A future direct browser SimpleX implementation should register itself with:

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
