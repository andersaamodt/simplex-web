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
- XFTP HTTPS encrypted-chunk upload through `fetch`.
- XFTP encrypted-chunk download, verification, and byte-for-byte reassembly.
- XFTP chunk deletion, followed by a failed re-download.

It does not send chat plaintext through a website server. The SMP endpoint sees
SMP protocol blocks. The XFTP endpoint sees encrypted chunks and metadata, not
file plaintext or the file root key.

## Required Endpoint Shape

The SMP server must expose the browser SMP WebSocket profile implemented by
`src/browser-smp-websocket-transport.mjs`:

- `wss://` outside local loopback development.
- Binary WebSocket frames only.
- Exactly one padded 16384-byte SMP transport block per frame after handshake.
- Server handshake first, then client handshake with the configured key hash.
- Compatible SMP version 3 or 4.
- Broker `PONG` response to an unauthenticated queue-empty `PING`.

The XFTP server must expose the HTTPS/fetch encrypted-chunk profile implemented
by `src/browser-xftp-http-transport.mjs`:

- `https://` endpoint outside local loopback development.
- `POST {base}/chunks` for encrypted chunk packets.
- `GET {base}/chunks/{fileId}/{index}` for encrypted chunk packets.
- `DELETE {base}/chunks/{fileId}/{index}` for test cleanup.
- JSON packets with base64url `ciphertext` and `tag` fields.

Point this harness only at a test profile or disposable namespace. The XFTP test
creates and deletes a unique encrypted test object.

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
SIMPLEX_WEB_LIVE_XFTP_HTTP_URL='https://xftp.example.test/xftp' \
SIMPLEX_WEB_LIVE_XFTP_KEY_HASH='BASE64URL_OR_HEX_HASH' \
SIMPLEX_WEB_LIVE_XFTP_ADDRESS='xftp://fingerprint@xftp.example.test' \
SIMPLEX_WEB_LIVE_XFTP_ORIGIN='https://site.example.test' \
npm run test:live
```

Optional variables:

- `SIMPLEX_WEB_LIVE_SMP_EXPECTED_SESSION_ID`: base64url or hex session id that
  must match the server handshake.
- `SIMPLEX_WEB_LIVE_TIMEOUT_MS`: per-step network timeout, default `15000`.
- `SIMPLEX_WEB_LIVE_XFTP_RETENTION_HOURS`: advertised test profile retention,
  default `24`.

## Release Meaning

A passing live run is necessary before claiming that a specific browser-profile
SMP/XFTP deployment interoperates with `simplex-web`.

It is still not the same as proving compatibility with existing raw TCP/TLS
SimpleX servers. Browsers cannot open raw TCP sockets or inspect the TLS
channel-binding data that native SimpleX clients use, so browser deployment
requires an explicitly reviewed browser transport profile.
