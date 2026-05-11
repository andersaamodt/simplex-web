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
