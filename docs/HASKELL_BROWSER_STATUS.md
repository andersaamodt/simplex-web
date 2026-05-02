# Haskell Browser Status

Goal: make `simplex-web` Haskell-first, ideally with GHC's browser-targeting path.

Current status in this workspace:

- no `ghc`
- no `cabal`
- no `stack`
- no `wasm32-wasi-ghc`
- no `ghc-wasm-meta`

Because of that, this repo currently ships the browser shell first.

That is not a rejection of Haskell. It is a sequencing choice:

- keep the browser UI and integration boundary moving
- avoid pretending a browser-native protocol core already exists
- leave a clean place to drop the Haskell core once the toolchain is available

If the Haskell browser toolchain becomes available, the intended direction is:

- Haskell owns protocol/core state transitions
- JavaScript remains a thin browser host layer
- this default UI can stay as the example renderer

