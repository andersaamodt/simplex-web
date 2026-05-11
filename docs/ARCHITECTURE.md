# Architecture

## Current boundary

`simplex-web` currently owns the browser-facing chat shell and the first Haskell-owned chat-state slice:

- HTML rendering for a single-thread secure chat surface
- message/status presentation
- upload progress presentation
- framework-free DOM mounting and event delegation
- bounded browser-local persistence for per-user chat continuity on the same browser/device
- UI callback surface for login, send, file-select, and admin actions
- Haskell-managed local chat state transitions exposed through browser-callable wasm exports
- a closed-by-default `window.SimplexWebTransport` facade for host-site integration
- a SimpleX Chat WebSocket adapter that can send through a browser-reachable SimpleX Chat command API

It does **not** yet own a handwritten SimpleX network/protocol transport core.

## Why

The upstream SimpleX code that exists today is centered on:

- native Haskell client and agent libraries
- local CLI / Node addon / WebSocket daemon integrations
- native app storage and transport assumptions

That means a truthful browser-native client needs new work in:

- browser-safe transport adaptation
- browser-safe durable state
- browser-safe key handling
- contact establishment and queue lifecycle in a browser runtime

Until that exists, the safest thing this repo can ship honestly is:

- the browser shell and integration boundary
- browser-local chat continuity that does not require the server to retain plaintext history
- Haskell-owned local chat state
- a host contract that proves Haskell/browser interop is workable before transport is attempted
- a transport API that refuses sends unless a browser-native adapter is explicitly registered
- a loopback-first adapter for the official SimpleX Chat command WebSocket, avoiding plaintext website relay when users provide a local/browser-reachable SimpleX endpoint

## Integration contract

The default UI expects a model shaped like:

```js
{
  loggedIn: true,
  hasSigner: true,
  error: "",
  sending: false,
  draftText: "",
  service: {
    transport_status: "connected",
    transport_error: ""
  },
  messages: [
    {
      direction: "incoming" | "outgoing",
      text: "hello",
      message_kind: "text" | "file",
      delivery_status: "sent",
      created_at: "2026-05-01T00:00:00Z",
      attachment: {
        name: "notes.txt",
        mime: "text/plain",
        size: 123
      }
    }
  ],
  uploads: [
    {
      upload_id: "upl-1",
      name: "notes.txt",
      status: "uploading",
      progress: 50
    }
  ],
  admin: false,
  adminMappings: []
}
```

The mount helper emits callbacks instead of owning transport:

- `onLogin()`
- `onSend(text)`
- `onDraftChange(text)`
- `onFilesSelected(files)`
- `onAdminRefresh()`
- `onAdminDeactivate(npub)`
- `onAdminDelete(npub)`

The transport facade exposed by `src/transport.js` is separate from the UI:

- `window.SimplexWebTransport.getStatus()`
- `window.SimplexWebTransport.connect(params)`
- `window.SimplexWebTransport.sendText({ contact_id, text, client_message_id })`
- `window.SimplexWebTransport.disconnect()`
- `window.SimplexWebTransport.registerBrowserTransport(adapter)`

Without an adapter, `sendText` rejects with `SIMPLEX_WEB_TRANSPORT_UNAVAILABLE`. This is the expected secure behavior; it keeps host sites from accidentally routing plaintext through a server bridge while still giving them a stable browser API to call.

`src/simplex-chat-websocket-adapter.js` provides the first real adapter. It registers via `registerBrowserTransport` and sends text through a SimpleX Chat command WebSocket:

- activate the configured SimpleX user with `/_user <user_id>`
- send to the configured contact with `/_send @<contact_id> json [...]`, including text sends, so message bodies remain structured content rather than command text
- normalize the SimpleX `newChatItems` response back into the facade receipt

The adapter only accepts loopback endpoints by default. Remote endpoints require `allowRemote: true` because they can see plaintext before SimpleX encrypts and sends through its own network transport.

## Next protocol steps

1. Keep the Haskell browser smoke and Haskell chat-core runtime tests green.
2. Expand the Haskell state core to cover contact/session lifecycle and persistence boundaries.
3. Keep the SimpleX Chat WebSocket adapter compatible with the official command API.
4. Move actual queue/contact/message transport logic into the Haskell core once the full browser transport boundary exists.
5. Keep this JS shell thin and disposable around that core.
