# Changelog

## 1.0.0 - 2026-05-10

- Stabilized the framework-free Secure Chat UI renderer and mount contract.
- Stabilized bounded browser-local session persistence.
- Added a closed-by-default `window.SimplexWebTransport` facade with explicit adapter registration.
- Kept plaintext server bridge fallback out of the transport path.
- Added focused adversarial input coverage for UI rendering, session storage, and transport normalization.
- Kept Haskell/WASM smoke and chat-core checks as explicit toolchain-dependent validation scripts.

Not included in `1.0.0`:

- Browser-native SimpleX protocol core.
- Direct browser SMP/XFTP transport.
- Checked-in Haskell/WASM build artifacts.
