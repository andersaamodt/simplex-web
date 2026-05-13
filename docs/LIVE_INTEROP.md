# Live Interoperability

`simplex-web` includes deterministic loopback tests by default. Those prove the
browser code can encode, encrypt, frame, upload, download, and reject hostile
inputs without depending on a public network service.

Full production interoperability needs one more class of evidence: live tests
against reviewed browser-profile SMP and XFTP servers. This repo now includes
that harness, but it is skipped unless you explicitly point it at disposable
reviewed endpoints.

## What This Tests

`npm run test:live` runs `tests/live-interop.test.mjs`.

When enabled, it checks:

- SMP-over-WebSocket handshake against a browser-profile SMP endpoint.
- Server identity hash bytes sent in the browser client handshake.
- Optional session-id binding when the endpoint publishes an expected session.
- One signed SMP `PING` transmission and matching broker `PONG` response.
- XFTP web HTTPS/fetch hello with a 32-byte browser challenge.
- XFTP web server identity proof verification against the configured key hash.
- XFTP web padded client handshake and binary `PING`/`PONG`.
- Optional destructive XFTP web file upload/download/delete round trip against
  a disposable endpoint, including file-envelope decryption, transport-encrypted
  `FGET` body decryption, and SHA-256 chunk digest verification.

It does not send chat plaintext through a website server. The SMP endpoint sees
SMP protocol blocks. The XFTP endpoint sees XFTP protocol blocks and encrypted
file chunks. The destructive XFTP test uploads, downloads, verifies, and deletes
one encrypted test file; keep it pointed at a disposable reviewed endpoint.

## Required Endpoint Shape

The SMP server must expose the browser SMP WebSocket profile implemented by
`src/browser-smp-websocket-transport.mjs`:

- `wss://` outside local loopback development.
- Binary WebSocket frames only.
- Exactly one padded 16384-byte SMP transport block per frame after handshake.
- Server handshake first, then client handshake with the configured key hash.
- Compatible SMP version 3, 4, 5, or 6.
- Broker `PONG` response to an unauthenticated queue-empty `PING`.

The XFTP server must expose the upstream-style XFTP web profile implemented by
`src/browser-xftp-web-client.mjs`:

- `https://` endpoint outside local loopback development.
- `POST {base}` with `xftp-web-hello: 1` for the padded browser hello.
- Padded server handshake containing version range, session id, certificate
  chain, signed server key, and web identity proof.
- `POST {base}` with `xftp-handshake: 1` for the padded client handshake.
- One padded 16384-byte XFTP command block per fetch request after handshake.
- Broker `PONG` response to an unauthenticated XFTP `PING`.
- Disposable file-command tests must support `FNEW`, `FPUT`, `FGET`, and `FDEL`;
  `FGET` must return a transport-encrypted chunk body decryptable with the
  response DH key and nonce. The client then verifies the encrypted file digest
  and decrypts the file-level XFTP envelope locally.

Point this harness only at a reviewed browser-profile endpoint. The default
live XFTP test is non-destructive.

## Run

With no environment variables, the live tests skip and pass:

```sh
npm run test:live
```

To run against reviewed endpoints:

```sh
SIMPLEX_WEB_LIVE_ENABLE=1 \
SIMPLEX_WEB_LIVE_SMP_WS_URL='wss://smp.example.test/smp' \
SIMPLEX_WEB_LIVE_SMP_KEY_HASH='BASE64URL_OR_HEX_HASH' \
SIMPLEX_WEB_LIVE_XFTP_WEB_URL='https://xftp.example.test/' \
SIMPLEX_WEB_LIVE_XFTP_KEY_HASH='BASE64URL_OR_HEX_HASH' \
npm run test:live
```

Optional variables:

- `SIMPLEX_WEB_LIVE_SMP_EXPECTED_SESSION_ID`: base64url or hex session id that
  must match the server handshake.
- `SIMPLEX_WEB_LIVE_TIMEOUT_MS`: per-step network timeout, default `15000`.
- `SIMPLEX_WEB_LIVE_XFTP_DESTRUCTIVE=1`: enables the disposable live XFTP
  file-command round trip.

## Release Meaning

A passing live run is necessary before claiming that a specific browser-profile
SMP/XFTP deployment interoperates with `simplex-web`.

It is still not the same as proving compatibility with existing raw TCP/TLS
SimpleX servers. Browsers cannot open raw TCP sockets or inspect the TLS
channel-binding data that native SimpleX clients use, so browser deployment
requires an explicitly reviewed browser transport profile.
