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
    message_ref: '123',
    chat_item: { meta: { itemId: 123, itemStatus: { type: 'sndSent' } } }
  });
  assert.equal(FakeWebSocket.sockets[0].closed, true);
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

test('websocket adapter requires active user and contact ids', async () => {
  const adapter = adapterApi.createSimplexChatWebSocketAdapter({
    url: 'ws://127.0.0.1:5225',
    WebSocketImpl: makeFakeWebSocket(() => {})
  });

  await assert.rejects(
    adapter.sendText({ contact_id: '42', text: 'hello' }),
    error => {
      assert.equal(error.code, adapterApi.ERROR_CONFIG);
      return true;
    }
  );
});
