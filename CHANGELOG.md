# Changelog

## 1.0.0 - 2026-05-11

- Stabilized the framework-free Secure Chat UI renderer and mount contract.
- Stabilized bounded browser-local session persistence.
- Added a closed-by-default `window.SimplexWebTransport` facade with explicit adapter registration.
- Added `src/simplex-chat-websocket-adapter.js` for browser sends through a browser-reachable SimpleX Chat command WebSocket.
- Hardened WebSocket send failure handling so synchronous socket failures reject and close cleanly.
- Added the optional loopback file bridge for browser `File` staging, with origin, symlink, size, and output-shape hardening.
- Hardened delegated UI click handling so actions resolved outside the mounted root are ignored.
- Kept plaintext server bridge fallback out of the transport path.
- Added focused adversarial input coverage for UI rendering, session storage, transport normalization, WebSocket failure paths, file bridge boundaries, and Safari/WebKit rendering behavior.
- Added live two-daemon SimpleX E2E coverage for the WebSocket adapter using temporary profiles.
- Added the 2026-05-11 external-review-style security review notes in `docs/SECURITY_REVIEW.md`.
- Proved the Haskell/WASM smoke and chat-core checks against `ghc-wasm-meta`'s `wasm32-wasi-ghc`.

Not included in `1.0.0`:

- Browser-native SimpleX protocol core.
- Direct browser SMP/XFTP transport.
- Checked-in Haskell/WASM build artifacts.
