# Architecture

## Current boundary

`simplex-web` currently owns the browser-facing chat shell and the first Haskell-owned chat-state slice:

- HTML rendering for a single-thread secure chat surface
- message/status presentation
- upload progress presentation
- framework-free DOM mounting and event delegation
- UI callback surface for login, send, file-select, and admin actions
- Haskell-managed local chat state transitions exposed through browser-callable wasm exports

It does **not** yet own the SimpleX network/protocol transport core.

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
- Haskell-owned local chat state
- a host contract that proves Haskell/browser interop is workable before transport is attempted

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

## Next protocol steps

1. Keep the Haskell browser smoke and Haskell chat-core runtime tests green.
2. Expand the Haskell state core to cover contact/session lifecycle and persistence boundaries.
3. Define a browser transport abstraction that does not pretend the current daemon bridge is browser-native.
4. Move actual queue/contact/message transport logic into the Haskell core once the transport boundary exists.
5. Keep this JS shell thin and disposable around that core.
