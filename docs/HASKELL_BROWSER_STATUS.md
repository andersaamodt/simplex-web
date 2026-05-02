# Haskell Browser Status

Goal: make `simplex-web` Haskell-first, ideally with GHC's browser-targeting path.

Current status in this workspace:

- no `ghc`
- no `cabal`
- no `stack`
- no `wasm32-wasi-ghc`
- no `ghc-wasm-meta`
- a Haskell/WASM smoke scaffold now exists in `haskell/src/Simplex/Web/Smoke.hs` and `tests-haskell-wasm-runtime.sh`

Because of that, this repo currently ships the browser shell first.

That is not a rejection of Haskell. It is a sequencing choice:

- keep the browser UI and integration boundary moving
- avoid pretending a browser-native protocol core already exists
- leave a clean place to drop the Haskell core once the toolchain is available

If the Haskell browser toolchain becomes available, the intended direction is:

- Haskell owns protocol/core state transitions
- JavaScript remains a thin browser host layer
- this default UI can stay as the example renderer

## 2026-05-02 installation attempt

I attempted the current official wasm toolchain path on this Apple Silicon machine using upstream `ghc-wasm-meta`.

Observed facts:

- the installer first downloads a `wasi-sdk` bindist of roughly `132 MB`
- after that, the actual `wasm32-wasi-ghc-gmp-aarch64-darwin-9.14` bindist is roughly `510 MB`
- the available download rate in this environment was only about `75-80 KB/s`

That makes the official wasm bootstrap path a multi-hour install here before any compile/test cycle can even begin.

I also probed the Homebrew `ghc` bottle as a possible fallback path, but it downloaded at the same constrained rate and does not by itself prove availability of the browser-targeted cross backend we need.

So the honest current state is:

- the browser-facing Haskell smoke scaffold is ready
- the toolchain install path has been identified and tested
- the remaining blocker on this machine is bindist download throughput, not project structure
