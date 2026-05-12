# Changelog

## Unreleased

- Removed the previous SimpleX Chat command API adapter, loopback file bridge,
  mock chat example, and live adapter tests so the package no longer ships a
  daemon-backed or plaintext compatibility path.
- Removed package exports, scripts, runtime checks, and README instructions for
  that deleted compatibility path.
- Added `src/browser-smp-core.mjs`, the first handwritten browser-native SMP protocol core slice.
- Added SMP queue URI parsing, command/broker-message codecs, signed transmission framing, fixed-size transport block padding, SMP v4 batching, and handshake helpers.
- Added browser-compatible Ed25519, X25519, XSalsa20-Poly1305, AES-GCM, and SHA-256 helpers through audited Noble JavaScript crypto packages.
- Added focused unit and fuzz coverage for the SMP core.
- Added `src/browser-simplex-agent.mjs`, the first browser-native SimpleX agent helper layer for encrypted client-message envelopes, queue creation, queue-scoped recipient commands, and initial sender confirmation messages.
- Added focused unit and fuzz coverage for the browser agent helper layer.
- Added `src/browser-simplex-client.mjs`, a queue-level browser SimpleX client orchestrator over abstract SMP transports.
- Added focused client tests for signed `NEW`, `SUB`, `ACK`, `KEY`, `DEL`, unsigned initial confirmation, broker errors, and hostile correlation IDs.
- Added `src/browser-smp-websocket-transport.mjs`, a binary SMP-over-WebSocket browser transport profile for compatible SMP servers.
- Added focused transport tests for URL policy, binary handshakes, block sending/receiving, malformed frames, and session mismatch handling.
- Documented the low-to-the-ground free-software design posture and distinguished the new SMP/agent helper layers from the still-missing full contact/double-ratchet/XFTP/browser-transport layers.

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

- Direct browser SMP/XFTP transport.
- Checked-in Haskell/WASM build artifacts.
