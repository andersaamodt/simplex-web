const test = require('node:test');
const assert = require('node:assert/strict');

const transportApi = require('../src/transport.js');
const adapterApi = require('../src/simplex-chat-websocket-adapter.js');

function makeFakeWebSocket(script) {
  const sockets = [];
  class FakeWebSocket {
    constructor(url) {
      this.url = url;
      this.sent = [];
      this.listeners = new Map();
      this.closed = false;
      sockets.push(this);
      queueMicrotask(() => this.emit('open', {}));
    }
    addEventListener(name, handler) {
      if (!this.listeners.has(name)) this.listeners.set(name, []);
      this.listeners.get(name).push(handler);
    }
    removeEventListener(name, handler) {
      const handlers = this.listeners.get(name) || [];
      this.listeners.set(name, handlers.filter((next) => next !== handler));
    }
    emit(name, event) {
      (this.listeners.get(name) || []).forEach((handler) => handler(event));
    }
    send(value) {
      this.sent.push(JSON.parse(value));
      script(this, this.sent[this.sent.length - 1], this.sent.length);
    }
    close() {
      this.closed = true;
    }
  }
  FakeWebSocket.sockets = sockets;
  return FakeWebSocket;
}

test('websocket adapter sends via active SimpleX Chat user and contact', async () => {
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    if (count === 1) {
      assert.equal(outbound.cmd, '/_user 7');
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser' } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @42 text hello');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'newChatItems',
          chatItems: [
            { chatItem: { meta: { itemId: 123, itemStatus: { type: 'sndSent' } } } }
          ]
        }
      })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    user_id: '7',
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({ contact_id: '42', text: 'hello', client_message_id: 'client-1' });
  assert.deepEqual(receipt, {
    accepted: true,
    transport_status: 'sent',
    raw_status: 'sndSent',
    message_ref: '123',
    chat_item: { meta: { itemId: 123, itemStatus: { type: 'sndSent' } } }
  });
  assert.equal(FakeWebSocket.sockets[0].closed, true);
});

test('websocket adapter preserves sndNew and reports later status updates', async () => {
  let sendItemId = '';
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser' } })
      }));
      return;
    }
    sendItemId = outbound.corrId;
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'newChatItems',
          chatItems: [
            { chatItem: { meta: { itemId: 124, itemStatus: { type: 'sndNew' } } } }
          ]
        }
      })
    }));
    setTimeout(() => socket.emit('message', {
      data: JSON.stringify({
        resp: {
          type: 'chatItemsStatusesUpdated',
          chatItems: [
            { chatItem: { meta: { itemId: 124, itemStatus: { type: 'sndRcvd' } } } }
          ]
        }
      })
    }), 10);
  });
  const statusUpdates = [];

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    user_id: '7',
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({
    contact_id: '42',
    text: 'hello',
    client_message_id: 'client-2',
    on_status(update) {
      statusUpdates.push(update);
    }
  });
  assert.ok(sendItemId);
  assert.equal(receipt.transport_status, 'sending');
  assert.equal(receipt.message_ref, '124');
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(statusUpdates.length, 1);
  assert.equal(statusUpdates[0].transport_status, 'delivered');
  assert.equal(statusUpdates[0].raw_status, 'sndRcvd');
});

test('websocket adapter polls SimpleX history when status event is missed', async () => {
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 7 } } })
      }));
      return;
    }
    if (count === 2) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({
          corrId: outbound.corrId,
          resp: {
            type: 'newChatItems',
            chatItems: [
              { chatItem: { meta: { itemId: 125, itemStatus: { type: 'sndNew' } } } }
            ]
          }
        })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_get chat @42 count=20');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'apiChat',
          chat: {
            chatItems: [
              { meta: { itemId: 125, itemStatus: { type: count === 3 ? 'sndSent' : 'sndRcvd' } } }
            ]
          }
        }
      })
    }));
  });
  const statusUpdates = [];

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    user_id: '7',
    status_timeout_ms: 2000,
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({
    contact_id: '42',
    text: 'hello',
    client_message_id: 'client-poll-1',
    on_status(update) {
      statusUpdates.push(update);
    }
  });
  assert.equal(receipt.transport_status, 'sending');
  await new Promise((resolve) => setTimeout(resolve, 1600));
  assert.deepEqual(commands.slice(0, 3), ['/_user 7', '/_send @42 text hello', '/_get chat @42 count=20']);
  assert.equal(statusUpdates.length, 2);
  assert.equal(statusUpdates[0].transport_status, 'sent');
  assert.equal(statusUpdates[0].raw_status, 'sndSent');
  assert.equal(statusUpdates[1].transport_status, 'delivered');
  assert.equal(statusUpdates[1].raw_status, 'sndRcvd');
  assert.equal(FakeWebSocket.sockets[0].closed, true);
});

test('websocket adapter reconnects contact link after stale cached contact id fails', async () => {
  const storage = new Map([[
    'simplex-chat-websocket-adapter-v1:example:npub1test:9:https://simplex.chat/contact#/?v=1&smp=stale',
    '12'
  ]]);
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    if (count === 2) {
      assert.equal(outbound.cmd, '/_send @12 text via stale cache');
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'chatCmdError', chatError: { type: 'contactNotFound' } } })
      }));
      return;
    }
    if (count === 3) {
      assert.equal(outbound.cmd, '/connect https://simplex.chat/contact#/?v=1&smp=stale');
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ resp: { type: 'contactAlreadyExists', contact: { contactId: 77 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @77 text via stale cache');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'newChatItems',
          chatItems: [
            { chatItem: { meta: { itemId: 126, itemStatus: { type: 'sndSent' } } } }
          ]
        }
      })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    storage: {
      getItem(key) { return storage.get(key) || null; },
      setItem(key, value) { storage.set(key, value); },
      removeItem(key) { storage.delete(key); }
    },
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({
    contact_link: 'https://simplex.chat/contact#/?v=1&smp=stale',
    siteKey: 'example',
    accountKey: 'npub1test',
    text: 'via stale cache',
    client_message_id: 'client-stale-1'
  });
  assert.deepEqual(commands, [
    '/u',
    '/_send @12 text via stale cache',
    '/connect https://simplex.chat/contact#/?v=1&smp=stale',
    '/_send @77 text via stale cache'
  ]);
  assert.equal(receipt.transport_status, 'sent');
  assert.equal(Array.from(storage.values())[0], '77');
});

test('websocket adapter can query a cached message status from SimpleX history', async () => {
  const storage = new Map([[
    'simplex-chat-websocket-adapter-v1:example:npub1test:9:https://simplex.chat/contact#/?v=1&smp=query',
    '77'
  ]]);
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_get chat @77 count=20');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'apiChat',
          chat: {
            chatItems: [
              { meta: { itemId: 126, itemStatus: { type: 'sndRcvd' } } }
            ]
          }
        }
      })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    storage: {
      getItem(key) { return storage.get(key) || null; },
      setItem(key, value) { storage.set(key, value); }
    },
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.getMessageStatus({
    contact_link: 'https://simplex.chat/contact#/?v=1&smp=query',
    siteKey: 'example',
    accountKey: 'npub1test',
    message_ref: '126'
  });
  assert.deepEqual(commands, ['/u', '/_get chat @77 count=20']);
  assert.equal(receipt.transport_status, 'delivered');
  assert.equal(receipt.raw_status, 'sndRcvd');
});

test('websocket adapter can query recent incoming SimpleX messages', async () => {
  const storage = new Map([[
    'simplex-chat-websocket-adapter-v1:example:npub1test:9:https://simplex.chat/contact#/?v=1&smp=receive',
    '77'
  ]]);
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_get chat @77 count=50');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'apiChat',
          chat: {
            chatItems: [
              {
                chatDir: { type: 'directRcv' },
                meta: { itemId: 201, itemStatus: { type: 'rcvNew' }, itemTs: '2026-05-11T00:00:00Z' },
                content: { msgContent: { type: 'text', text: 'reply from owl native' } }
              },
              {
                chatDir: { type: 'directSnd' },
                meta: { itemId: 202, itemStatus: { type: 'sndRcvd' }, itemTs: '2026-05-11T00:00:01Z' },
                content: { msgContent: { type: 'text', text: 'local outgoing' } }
              }
            ]
          }
        }
      })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    storage: {
      getItem(key) { return storage.get(key) || null; },
      setItem(key, value) { storage.set(key, value); }
    },
    WebSocketImpl: FakeWebSocket
  });

  const messages = await adapter.getMessages({
    contact_link: 'https://simplex.chat/contact#/?v=1&smp=receive',
    siteKey: 'example',
    accountKey: 'npub1test'
  });
  assert.deepEqual(commands, ['/u', '/_get chat @77 count=50']);
  assert.equal(messages.length, 2);
  assert.equal(messages[0].direction, 'incoming');
  assert.equal(messages[0].delivery_status, 'received');
  assert.equal(messages[0].message_ref, '201');
  assert.equal(messages[0].text, 'reply from owl native');
  assert.equal(messages[1].direction, 'outgoing');
  assert.equal(messages[1].delivery_status, 'delivered');
});

test('websocket adapter sends attachments with the official SimpleX file JSON command', async () => {
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @77 json [{"fileSource":{"filePath":"/tmp/probe-😀.txt"},"msgContent":{"type":"file","text":"caption with attachment"},"mentions":{}}]');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'newChatItems',
          chatItems: [
            { chatItem: { meta: { itemId: 301, itemStatus: { type: 'sndSent' } } } }
          ]
        }
      })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    user_id: '9',
    WebSocketImpl: FakeWebSocket
  });
  const receipts = await adapter.sendFiles({
    contact_id: '77',
    text: 'caption with attachment',
    files: [{
      name: 'probe-😀.txt',
      size: 5,
      type: 'text/plain',
      simplexFilePath: '/tmp/probe-😀.txt'
    }]
  });

  assert.deepEqual(commands, [
    '/_user 9',
    '/_send @77 json [{"fileSource":{"filePath":"/tmp/probe-😀.txt"},"msgContent":{"type":"file","text":"caption with attachment"},"mentions":{}}]'
  ]);
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].transport_status, 'sent');
  assert.equal(receipts[0].attachment.name, 'probe-😀.txt');
  assert.equal(receipts[0].attachment.mime, 'text/plain');
  assert.equal(receipts[0].attachment.size, 5);
  assert.equal(receipts[0].attachment.file_path, '/tmp/probe-😀.txt');
  assert.equal(receipts[0].attachment.data_url, '');
});

test('websocket adapter stages browser File attachments through a loopback file bridge', async () => {
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @77 json [{"fileSource":{"filePath":"/tmp/simplex-web/probe.txt"},"msgContent":{"type":"file","text":""},"mentions":{}}]');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'newChatItems',
          chatItems: [
            { chatItem: { meta: { itemId: 303, itemStatus: { type: 'sndSent' } } } }
          ]
        }
      })
    }));
  });

  const fetchCalls = [];
  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    fileBridgeUrl: 'http://127.0.0.1:5226',
    user_id: '9',
    WebSocketImpl: FakeWebSocket,
    fetchImpl(url, options) {
      fetchCalls.push({ url, options });
      return Promise.resolve({
        ok: true,
        json() {
          return Promise.resolve({ filePath: '/tmp/simplex-web/probe.txt' });
        }
      });
    }
  });

  const receipts = await adapter.sendFiles({
    contact_id: '77',
    files: [{ name: 'probe.txt', size: 5, type: 'text/plain' }]
  });

  assert.equal(fetchCalls.length, 1);
  assert.equal(fetchCalls[0].url, 'http://127.0.0.1:5226/files');
  assert.equal(fetchCalls[0].options.headers['X-File-Name'], 'probe.txt');
  assert.deepEqual(commands, [
    '/_user 9',
    '/_send @77 json [{"fileSource":{"filePath":"/tmp/simplex-web/probe.txt"},"msgContent":{"type":"file","text":""},"mentions":{}}]'
  ]);
  assert.equal(receipts[0].attachment.file_path, '/tmp/simplex-web/probe.txt');
});

test('websocket adapter binds native browser fetch when staging browser File attachments', async () => {
  const originalFetch = global.fetch;
  const commands = [];
  const fetchCalls = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @77 json [{"fileSource":{"filePath":"/tmp/simplex-web/window-bound.txt"},"msgContent":{"type":"file","text":""},"mentions":{}}]');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'newChatItems',
          chatItems: [
            { chatItem: { meta: { itemId: 304, itemStatus: { type: 'sndSent' } } } }
          ]
        }
      })
    }));
  });

  global.fetch = function strictWindowFetch(url, options) {
    assert.equal(this, global);
    fetchCalls.push({ url, options });
    return Promise.resolve({
      ok: true,
      json() {
        return Promise.resolve({ filePath: '/tmp/simplex-web/window-bound.txt' });
      }
    });
  };

  try {
    const adapter = adapterApi.createSimplexChatWebSocketAdapter({
      url: 'ws://127.0.0.1:5225',
      fileBridgeUrl: 'http://127.0.0.1:5226',
      user_id: '9',
      WebSocketImpl: FakeWebSocket
    });

    const receipts = await adapter.sendFiles({
      contact_id: '77',
      files: [{ name: 'window-bound.txt', size: 5, type: 'text/plain' }]
    });

    assert.equal(fetchCalls.length, 1);
    assert.equal(fetchCalls[0].url, 'http://127.0.0.1:5226/files');
    assert.deepEqual(commands, [
      '/_user 9',
      '/_send @77 json [{"fileSource":{"filePath":"/tmp/simplex-web/window-bound.txt"},"msgContent":{"type":"file","text":""},"mentions":{}}]'
    ]);
    assert.equal(receipts[0].attachment.file_path, '/tmp/simplex-web/window-bound.txt');
  } finally {
    global.fetch = originalFetch;
  }
});

test('websocket adapter fails closed for browser File attachments without a path or loopback bridge', async () => {
  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    user_id: '9',
    WebSocketImpl: makeFakeWebSocket(() => {})
  });

  await assert.rejects(
    adapter.sendFiles({
      contact_id: '77',
      files: [{ name: 'probe.txt', size: 5, type: 'text/plain' }]
    }),
    /loopback simplex-web file bridge/
  );
});

test('websocket adapter parses SimpleX text envelope attachments from history', async () => {
  const marker = 'simplex-web-file:v1:eyJuYW1lIjoicHJvYmUt8J-YgC50eHQiLCJtaW1lIjoidGV4dC9wbGFpbiIsInNpemUiOjV9:aGVsbG8=';
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'apiChat',
          chat: {
            chatItems: [
              {
                chatDir: { type: 'directRcv' },
                meta: { itemId: 302, itemStatus: { type: 'rcvNew' }, itemTs: '2026-05-11T00:00:00Z' },
                content: { msgContent: { type: 'text', text: 'Attachment: probe-😀.txt\n' + marker } }
              }
            ]
          }
        }
      })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    user_id: '9',
    WebSocketImpl: FakeWebSocket
  });

  const messages = await adapter.getMessages({ contact_id: '77' });
  assert.equal(messages[0].message_kind, 'file');
  assert.equal(messages[0].text, 'Attachment: probe-😀.txt');
  assert.equal(messages[0].attachment.name, 'probe-😀.txt');
  assert.equal(messages[0].attachment.mime, 'text/plain');
  assert.equal(messages[0].attachment.size, 5);
  assert.equal(messages[0].attachment.data_url, 'data:text/plain;base64,aGVsbG8=');
});

test('websocket adapter ignores unsolicited startup events before active user response', async () => {
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ resp: { type: 'connectionsDiff' } })
      }));
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 1 } } })
      }));
      return;
    }
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'newChatItems', chatItems: [] } })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({ contact_id: '42', text: 'hello', client_message_id: 'client-1' });
  assert.equal(receipt.message_ref, 'client-1');
});

test('websocket adapter can register as SimplexWebTransport adapter', async () => {
  global.SimplexWebTransport = transportApi;
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: count === 1
          ? { type: 'activeUser' }
          : { type: 'newChatItems', chatItems: [] }
      })
    }));
  });

  const transport = adapterApi.registerSimplexChatWebSocketTransport({
    url: 'ws://localhost:5225',
    user_id: '11',
    WebSocketImpl: FakeWebSocket
  });

  assert.equal(transport.isAvailable(), true);
  assert.deepEqual(transport.getStatus(), {
    available: true,
    transport_status: 'simplex-chat-websocket',
    transport_error: ''
  });
  const receipt = await transport.sendText({ contact_id: '5', text: 'registered', client_message_id: 'fallback-ref' });
  assert.equal(receipt.message_ref, 'fallback-ref');
});

test('websocket adapter can connect a browser-local contact link before sending', async () => {
  const storage = new Map();
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    if (count === 1) {
      assert.equal(outbound.cmd, '/u');
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    if (count === 2) {
      assert.equal(outbound.cmd, '/connect https://simplex.chat/contact#/?v=1&smp=test');
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'sentInvitation' } })
      }));
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ resp: { type: 'contactConnected', contact: { contactId: 77 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @77 text via link');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'newChatItems', chatItems: [] } })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    storage: {
      getItem(key) { return storage.get(key) || null; },
      setItem(key, value) { storage.set(key, value); }
    },
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({
    contact_link: 'https://simplex.chat/contact#/?v=1&smp=test',
    siteKey: 'example',
    accountKey: 'npub1test',
    text: 'via link',
    client_message_id: 'client-link-1'
  });
  assert.equal(receipt.message_ref, 'client-link-1');
  assert.equal(Array.from(storage.values())[0], '77');
});

test('websocket adapter can reuse a known contact address connection plan', async () => {
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    if (count === 2) {
      assert.equal(outbound.cmd, '/connect https://simplex.chat/contact#/?v=1&smp=known');
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({
          corrId: outbound.corrId,
          resp: {
            type: 'connectionPlan',
            connectionPlan: {
              contactAddressPlan: {
                contact: { contactId: 88 }
              }
            }
          }
        })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @88 text via known plan');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'newChatItems', chatItems: [] } })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({
    contact_link: 'https://simplex.chat/contact#/?v=1&smp=known',
    text: 'via known plan',
    client_message_id: 'known-plan-1'
  });
  assert.equal(receipt.message_ref, 'known-plan-1');
});

test('websocket adapter rejects command-shaped identifiers before opening a socket', async () => {
  let opened = 0;
  class CountingWebSocket {
    constructor() {
      opened += 1;
    }
  }
  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: CountingWebSocket
  });

  await assert.rejects(
    adapter.sendText({ user_id: '7\n/_send @1 text pwn', contact_id: '42', text: 'hello' }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_CONFIG);
      return true;
    }
  );
  await assert.rejects(
    adapter.sendText({ user_id: '7', contact_id: '42 /_send @1 text pwn', text: 'hello' }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_CONFIG);
      return true;
    }
  );
  assert.equal(opened, 0);
});

test('websocket adapter rejects command-shaped contact links before opening a socket', async () => {
  let opened = 0;
  class CountingWebSocket {
    constructor() {
      opened += 1;
    }
  }
  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: CountingWebSocket
  });

  await assert.rejects(
    adapter.sendText({
      contact_link: 'https://simplex.chat/contact#/?v=1&smp=ok\n/_send @1 text pwn',
      text: 'hello'
    }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_CONFIG);
      return true;
    }
  );
  assert.equal(opened, 0);
});

test('websocket adapter ignores poisoned cached contact ids and reconnects the contact link', async () => {
  const storage = new Map([[
    'simplex-chat-websocket-adapter-v1:example:npub1test:9:https://simplex.chat/contact#/?v=1&smp=poison',
    '77\n/_send @1 text pwn'
  ]]);
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    if (count === 2) {
      assert.equal(outbound.cmd, '/connect https://simplex.chat/contact#/?v=1&smp=poison');
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ resp: { type: 'contactConnected', contact: { contactId: 88 } } })
      }));
      return;
    }
    assert.equal(outbound.cmd, '/_send @88 text recovered');
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'newChatItems', chatItems: [] } })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    storage: {
      getItem(key) { return storage.get(key) || null; },
      setItem(key, value) { storage.set(key, value); },
      removeItem(key) { storage.delete(key); }
    },
    WebSocketImpl: FakeWebSocket
  });

  const receipt = await adapter.sendText({
    contact_link: 'https://simplex.chat/contact#/?v=1&smp=poison',
    siteKey: 'example',
    accountKey: 'npub1test',
    text: 'recovered',
    client_message_id: 'poison-cache-1'
  });
  assert.deepEqual(commands, [
    '/u',
    '/connect https://simplex.chat/contact#/?v=1&smp=poison',
    '/_send @88 text recovered'
  ]);
  assert.equal(receipt.message_ref, 'poison-cache-1');
  assert.equal(Array.from(storage.values())[0], '88');
});

test('websocket adapter rejects command-shaped contact ids returned by SimpleX before sending', async () => {
  const commands = [];
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    commands.push(outbound.cmd);
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 9 } } })
      }));
      return;
    }
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({ resp: { type: 'contactConnected', contact: { contactId: '88\n/_send @1 text pwn' } } })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: FakeWebSocket
  });

  await assert.rejects(
    adapter.sendText({
      contact_link: 'https://simplex.chat/contact#/?v=1&smp=bad-response',
      text: 'hello'
    }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_CONFIG);
      return true;
    }
  );
  assert.deepEqual(commands, [
    '/u',
    '/connect https://simplex.chat/contact#/?v=1&smp=bad-response'
  ]);
});

test('websocket adapter rejects relative paths returned by the file bridge', async () => {
  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    fileBridgeUrl: 'http://127.0.0.1:5226',
    user_id: '9',
    WebSocketImpl: makeFakeWebSocket(() => {
      throw new Error('socket should not open after unsafe bridge path');
    }),
    fetchImpl() {
      return Promise.resolve({
        ok: true,
        json() {
          return Promise.resolve({ filePath: '../../etc/passwd' });
        }
      });
    }
  });

  await assert.rejects(
    adapter.sendFiles({
      contact_id: '77',
      files: [{ name: 'probe.txt', size: 5, type: 'text/plain' }]
    }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_RESPONSE);
      return true;
    }
  );
});

test('websocket adapter reports SimpleX broker connection errors', async () => {
  const FakeWebSocket = makeFakeWebSocket((socket, outbound, count) => {
    if (count === 1) {
      queueMicrotask(() => socket.emit('message', {
        data: JSON.stringify({ corrId: outbound.corrId, resp: { type: 'activeUser', user: { userId: 1 } } })
      }));
      return;
    }
    queueMicrotask(() => socket.emit('message', {
      data: JSON.stringify({
        corrId: outbound.corrId,
        resp: {
          type: 'chatCmdError',
          chatError: {
            type: 'errorAgent',
            agentError: {
              type: 'BROKER',
              brokerAddress: 'smp://example@smp.example',
              brokerErr: { type: 'TIMEOUT' }
            }
          }
        }
      })
    }));
  });

  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: FakeWebSocket
  });
  await assert.rejects(
    adapter.sendText({ contact_link: 'simplex:/contact#broken', text: 'hello' }),
    /BROKER TIMEOUT smp:\/\/example@smp\.example/
  );
});

test('websocket adapter rejects remote endpoints unless explicitly allowed', () => {
  assert.throws(
    () => adapterApi.createSimplexChatWebSocketAdapter({
      url: 'wss://example.com/simplex',
      user_id: '1',
      WebSocketImpl: makeFakeWebSocket(() => {})
    }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_SECURITY);
      return true;
    }
  );

  assert.doesNotThrow(() => adapterApi.createSimplexChatWebSocketAdapter({
    url: 'wss://example.com/simplex',
    allowRemote: true,
    user_id: '1',
    WebSocketImpl: makeFakeWebSocket(() => {})
  }));
});

test('websocket adapter requires a contact id or contact link', async () => {
  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: makeFakeWebSocket(() => {})
  });

  await assert.rejects(
    adapter.sendText({ text: 'hello' }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_CONFIG);
      return true;
    }
  );
});
