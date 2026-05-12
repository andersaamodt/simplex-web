# Security Review

Date: 2026-05-11

Reviewer posture: Codex Desktop external-review simulation. This is not an
independent third-party human audit, but it was performed adversarially against
the code, tests, browser surface, and live SimpleX daemon behavior available in
this local environment.

## Scope

Reviewed release surface:

- `src/default-chat.js` and `src/default-chat.css`
- `src/session-store.js`
- `src/transport.js`
- `src/simplex-chat-websocket-adapter.js`
- `scripts/simplex-web-file-bridge.mjs`
- Haskell/WASM scaffolds and runtime wrappers
- Browser examples and release documentation

Out of scope:

- Upstream SimpleX cryptographic protocol correctness.
- A handwritten browser-native SMP/XFTP transport, which this release does not
  ship.
- Security of remote SimpleX Chat WebSocket endpoints operated by someone else.

## Threat Model

Primary assets:

- Plaintext message text before it reaches a local SimpleX daemon.
- Browser-local chat history and draft state.
- Local files staged through the optional file bridge.
- Contact identifiers, contact links, and SimpleX daemon command strings.
- Browser DOM integrity when rendering hostile imported messages or metadata.

Primary attacker capabilities tested:

- Inject hostile HTML, event handler strings, JavaScript URLs, oversized data,
  control characters, Unicode edge cases, and command-shaped message bodies.
- Poison browser storage and cached contact IDs.
- Return malformed WebSocket responses from the SimpleX Chat API.
- Make WebSocket sends throw or race page lifecycle close events.
- Abuse the file bridge with hostile origins, traversal, symlinks, oversized
  uploads, malformed names, and MIME confusion.
- Force browser rendering/layout stress across desktop and mobile viewports.

## Findings

### Fixed: new SimpleX contacts could be used before ready

Live daemon probing showed that a contact can appear in `/chats` before the
daemon accepts sends to it. The previous retry loop was too short for this
condition. The adapter now recognizes `contactNotReady`, increases the default
retry count, and applies real backoff before retrying.

Coverage added:

- Unit regression for `contactNotReady` backoff.
- Live two-daemon E2E with temporary profiles and real SimpleX network setup.

### Fixed: command-shaped text is structured content

Text sends use the SimpleX Chat JSON composed-message command shape:

```text
/_send @<contact_id> json [{"msgContent":{"type":"text","text":"..."},"mentions":{}}]
```

The live daemon test sends a body containing a newline plus a second
command-looking string and verifies the peer receives it as literal message
content.

### Accepted residual risk: local SimpleX WebSocket plaintext boundary

The WebSocket adapter necessarily sends plaintext to a browser-reachable SimpleX
Chat command API before the SimpleX daemon encrypts it for the network. This is
why the adapter rejects remote WebSocket endpoints by default. Remote endpoints
require explicit `allowRemote: true` and should be treated as trusted local
infrastructure, not a website bridge.

### Accepted residual risk: no direct browser SMP/XFTP transport

This release does not claim to include a handwritten browser-native SimpleX
protocol implementation. The fail-closed transport facade remains correct when
no adapter is registered.

## Executed Coverage

Automated:

- `npm test`
- `npm run test:fuzz`
- `npm run test:browser`
- `npm run test:live`
- `npm audit --audit-level=moderate`
- `npm pack --dry-run --json`

Manual/browser:

- Safari automation probe using hostile message text, attachment metadata,
  textarea content, remote attachment URL, and viewport overflow check.

Toolchain-dependent:

- `npm run test:haskell` when `wasm32-wasi-ghc` is installed.
- Official `ghc-wasm-meta` bootstrap attempted into `/tmp/simplex-web-ghc-wasm`
  during this review; see `docs/HASKELL_BROWSER_STATUS.md` for the current
  result.

## Release Posture

The release is suitable to describe as:

> adversarially tested by Codex Desktop across unit, integration, property/fuzz,
> browser, Safari automation, live SimpleX daemon E2E, packaging, and dependency
> audit coverage available in this environment.

Do not describe it as:

- browser-native direct SMP/XFTP
- independently audited by a third-party security firm
- mathematically bulletproof
- free of all future protocol, browser, or upstream daemon compatibility risk
