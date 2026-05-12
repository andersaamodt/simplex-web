# Haskell Browser Status

Goal: keep `simplex-web` Haskell-first where browser tooling supports it, while
not overstating the parts of SimpleX that this package does not implement.

## Current Status

The repository ships two Haskell/WASM validation slices:

- `haskell/src/Simplex/Web/Smoke.hs`: minimal reactor exports for browser/WASI
  instantiation.
- `haskell/src/Simplex/Web/Core.hs`: Haskell-owned chat-state transitions with
  JS-string exports for the browser host.

During the 1.0 release hardening pass, the official `ghc-wasm-meta` toolchain
bootstrap completed in this Codex Desktop environment:

- install root: `/tmp/simplex-web-ghc-wasm`
- env file: `/tmp/simplex-web-ghc-wasm/env`
- `wasm32-wasi-ghc`: `9.14.1.20260330`
- `wasm32-wasi-cabal`: `3.14.2.0`

With that env sourced, `npm run test:haskell` passes:

- Haskell smoke reactor compile and WASI runtime checks: 2 tests passed.
- Haskell chat core compile, post-link JSFFI generation, and runtime checks:
  5 tests passed.

Generated wasm and JSFFI glue are test artifacts under `build/`; they are
ignored and not checked into the package.

## What This Proves

- The repo's Haskell browser-target scaffolds compile with the official wasm
  GHC toolchain.
- The compiled smoke reactor can be instantiated from Node/WASI.
- The compiled chat core exports are callable from JavaScript through the
  generated JSFFI glue.
- Hostile text, status strings, oversize values, missing identifiers, retained
  history bounds, and upload progress bounds are covered at the Haskell state
  layer.

## What This Does Not Prove

- A browser-native SimpleX SMP/XFTP transport exists in this package.
- Upstream SimpleX protocol, cryptography, broker behavior, or queue semantics
  are verified by the Haskell scaffolds.
- Browser support for the future full protocol core is complete across every
  engine.

The release remains honest: Haskell owns the current state-core slice, while
actual network transport is still provided by the SimpleX Chat WebSocket adapter
or by a future browser-native transport adapter.
