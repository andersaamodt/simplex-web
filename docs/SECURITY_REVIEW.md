# Security Review

Date: 2026-05-11

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
- `src/browser-smp-websocket-transport.mjs`
- Haskell/WASM scaffolds and runtime wrappers
- Browser examples and release documentation

Explicitly not shipped or reviewed as a release feature:

- A SimpleX Chat command API adapter.
- A loopback file bridge.
- A mock chat transport.
- A plaintext website/server bridge.
- Upstream SimpleX cryptographic protocol correctness.
- Full contact state, double ratchet persistence, XFTP, and production browser
  SMP server deployment.

## Threat Model

Primary assets:

- Browser-local chat history and draft state.
- SMP queue IDs, correlation IDs, signed transmissions, and broker responses.
- Browser-held signing, DH, and message encryption keys.
- Browser DOM integrity when rendering hostile imported messages or metadata.
- Package integrity, so removed plaintext paths cannot be imported accidentally.

Primary attacker capabilities tested:

- Inject hostile HTML, event handler strings, JavaScript URLs, oversized data,
  control characters, Unicode edge cases, and malformed attachment metadata.
- Poison browser storage and cached labels.
- Feed malformed SMP queue URIs, commands, broker messages, transport blocks,
  handshakes, encrypted envelopes, and correlation IDs.
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

### Accepted residual risk: browser WebSocket SMP profile is not raw TCP/TLS SMP

Ordinary browser JavaScript cannot open raw TCP sockets, inspect TLS channel
binding, or pin server certificate bytes the same way a native SimpleX client
can. The current network-facing module is therefore an explicit browser
SMP-over-WebSocket profile for compatible servers, not a claim that browsers can
directly speak the existing raw TCP/TLS SMP transport.

### Accepted residual risk: full browser agent is still incomplete

The repo now contains real browser-native SMP primitives, agent envelope helpers,
queue orchestration, and a WebSocket block transport profile. It does not yet
contain the complete contact state machine, durable ratchet store, retry
scheduler, XFTP implementation, or production server deployment profile.

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
