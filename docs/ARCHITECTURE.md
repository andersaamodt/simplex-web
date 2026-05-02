# Architecture

## Current boundary

`simplex-web` currently owns the browser-facing chat shell:

- HTML rendering for a single-thread secure chat surface
- message/status presentation
- upload progress presentation
- framework-free DOM mounting and event delegation
- UI callback surface for login, send, file-select, and admin actions

It does **not** yet own the SimpleX protocol core.

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

Until that exists, the safest thing this repo can ship honestly is the browser shell and integration boundary.

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

1. Get a Haskell browser-targeting toolchain working for the `Simplex.Web.Smoke` reactor and keep that smoke test green.
2. Define a browser transport abstraction that does not pretend the current daemon bridge is browser-native.
3. Move queue/contact/message state transitions into the Haskell core once the toolchain exists.
4. Keep this JS shell thin and disposable around that core.
