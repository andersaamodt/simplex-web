# simplex-web

`simplex-web` is an experimental browser-hosted chat client shell for SimpleX.

Current scope:
- Ships a plain-JavaScript default chat UI that can be embedded into a hosted site.
- Includes a minimal Haskell-to-wasm reactor smoke test so browser-targeted Haskell can be validated honestly instead of hand-waved.
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
- `examples/mock-chat.html`: runnable browser example with a mocked chat state.
- `tests/default-chat.test.js`: Node unit tests for HTML contract, escaping, and status mapping.
- `tests-simplex-web-runtime.sh`: Wizardry-style shell wrapper around the focused runtime checks.
- `haskell/src/Simplex/Web/Smoke.hs`: first Haskell/WASM smoke module exported as a reactor.
- `tests/haskell-smoke.test.cjs`: Node/WASI runtime checks for the compiled reactor exports.
- `tests-haskell-wasm-runtime.sh`: Wizardry-style shell wrapper that compiles the Haskell smoke module and executes the runtime checks.
- `examples/haskell-smoke.html`: browser smoke page for the compiled Haskell reactor.
- `docs/ARCHITECTURE.md`: current boundaries and next protocol steps.
- `docs/HASKELL_BROWSER_STATUS.md`: current Haskell/browser status and why the UI ships first.

## Run

```sh
node --test tests/default-chat.test.js
./tests-simplex-web-runtime.sh
./tests-haskell-wasm-runtime.sh
```
