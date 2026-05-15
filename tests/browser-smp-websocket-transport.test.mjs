import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SMP_BLOCK_SIZE,
  asciiBytes,
  decodeTransportBlock,
  encodeTransportBlock,
  encodeServerHandshake,
  encodeSignedTransmission,
  equalBytes,
  parseClientHandshake,
  padBlock,
  unpadBlock
} from '../src/browser-smp-core.mjs';
import {
  connectBrowserSmpWebSocketTransport,
  normalizeSmpWebSocketUrl
} from '../src/browser-smp-websocket-transport.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

class FakeWebSocket {
  static instances = [];

  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.readyState = 0;
    this.binaryType = '';
    this.sent = [];
    this.listeners = new Map();
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(handler);
  }

  removeEventListener(type, handler) {
    if (this.listeners.has(type)) this.listeners.get(type).delete(handler);
  }

  send(data) {
    this.sent.push(data);
  }

  close() {
    if (this.readyState >= 2) return;
    this.readyState = 3;
    this.emit('close', {});
  }

  open() {
    this.readyState = 1;
    this.emit('open', {});
  }

  message(data) {
    this.emit('message', { data });
  }

  emit(type, event) {
    for (const handler of this.listeners.get(type) || []) handler(event);
  }
}

function resetSockets() {
  FakeWebSocket.instances = [];
}

function nextTurn() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

test('SMP WebSocket URL normalization rejects unsafe remote plaintext transports', () => {
  assert.equal(normalizeSmpWebSocketUrl('wss://smp.example/ws'), 'wss://smp.example/ws');
  assert.equal(normalizeSmpWebSocketUrl('ws://127.0.0.1:5223/ws'), 'ws://127.0.0.1:5223/ws');
  assert.throws(() => normalizeSmpWebSocketUrl('http://example.test'), /must use ws/);
  assert.throws(() => normalizeSmpWebSocketUrl('ws://smp.example/ws'), /must use wss/);
  assert.equal(normalizeSmpWebSocketUrl('ws://smp.example/ws', { allowInsecureRemote: true }), 'ws://smp.example/ws');
});

test('connects with binary SMP handshake and sends padded transport blocks', async () => {
  resetSockets();
  const connecting = connectBrowserSmpWebSocketTransport({
    url: 'wss://smp.example/ws',
    keyHash: filled(32, 1),
    WebSocketImpl: FakeWebSocket,
    timeoutMs: 1000
  });
  const socket = FakeWebSocket.instances[0];
  assert.deepEqual(socket.protocols, ['simplex-smp.v4.ws']);
  socket.open();
  await nextTurn();
  socket.message(padBlock(encodeServerHandshake({
    minVersion: 3,
    maxVersion: 4,
    sessionId: filled(32, 2)
  })).buffer);

  const transport = await connecting;
  assert.equal(transport.version, 4);
  assert.equal(transport.profile, 'simplex-smp-websocket-browser-v1');
  assert.equal(transport.security.plaintextBridge, false);
  assert.equal(transport.security.binarySmpBlocksOnly, true);
  assert.equal(socket.sent.length, 1);

  const clientHandshake = parseClientHandshake(unpadBlock(new Uint8Array(socket.sent[0])));
  assert.equal(clientHandshake.version, 4);
  assert.equal(equalBytes(clientHandshake.keyHash, filled(32, 1)), true);

  const tx = encodeSignedTransmission(4, filled(32, 2), {
    signature: new Uint8Array(),
    corrId: asciiBytes('ping-1'),
    queueId: new Uint8Array(),
    command: { type: 'PING' }
  });
  transport.sendSignedTransmissions([tx]);
  assert.equal(socket.sent.length, 2);
  assert.equal(new Uint8Array(socket.sent[1]).length, SMP_BLOCK_SIZE);
  const decoded = decodeTransportBlock(4, new Uint8Array(socket.sent[1]));
  assert.equal(decoded[0].command.type, 'PING');
});

test('caps default negotiated version at the implemented browser SMP maximum', async () => {
  resetSockets();
  const connecting = connectBrowserSmpWebSocketTransport({
    url: 'wss://smp.example/ws',
    keyHash: filled(32, 9),
    WebSocketImpl: FakeWebSocket,
    timeoutMs: 1000
  });
  const socket = FakeWebSocket.instances[0];
  socket.open();
  await nextTurn();
  socket.message(padBlock(encodeServerHandshake({
    minVersion: 3,
    maxVersion: 15,
    sessionId: filled(32, 10)
  })).buffer);

  const transport = await connecting;
  assert.equal(transport.version, 9);
  const clientHandshake = parseClientHandshake(unpadBlock(new Uint8Array(socket.sent[0])));
  assert.equal(clientHandshake.version, 9);
  transport.close();
});

test('receives binary SMP blocks and decodes signed transmissions', async () => {
  resetSockets();
  const connecting = connectBrowserSmpWebSocketTransport({
    url: 'wss://smp.example/ws',
    WebSocketImpl: FakeWebSocket,
    timeoutMs: 1000
  });
  const socket = FakeWebSocket.instances[0];
  socket.open();
  await nextTurn();
  socket.message(padBlock(encodeServerHandshake({
    minVersion: 4,
    maxVersion: 4,
    sessionId: filled(32, 3)
  })).buffer);
  const transport = await connecting;

  const tx = encodeSignedTransmission(4, filled(32, 3), {
    signature: new Uint8Array(),
    corrId: asciiBytes('sub-1'),
    queueId: filled(24, 4),
    command: { type: 'SUB' }
  });
  socket.message(encodeTransportBlock(4, [tx]).buffer);
  const received = await transport.receiveSignedTransmissions({ timeoutMs: 1000 });
  assert.equal(received[0].command.type, 'SUB');
  assert.equal(equalBytes(received[0].queueId, filled(24, 4)), true);
});

test('rejects text frames and malformed frame sizes', async () => {
  resetSockets();
  const connecting = connectBrowserSmpWebSocketTransport({
    url: 'wss://smp.example/ws',
    WebSocketImpl: FakeWebSocket,
    timeoutMs: 1000
  });
  const socket = FakeWebSocket.instances[0];
  socket.open();
  await nextTurn();
  socket.message('not binary');
  await assert.rejects(connecting, /non-binary frame/);

  resetSockets();
  const connectingBadSize = connectBrowserSmpWebSocketTransport({
    url: 'wss://smp.example/ws',
    WebSocketImpl: FakeWebSocket,
    timeoutMs: 1000
  });
  const socketBadSize = FakeWebSocket.instances[0];
  socketBadSize.open();
  await nextTurn();
  socketBadSize.message(new Uint8Array(10).buffer);
  await assert.rejects(connectingBadSize, /exactly one 16384-byte block/);
});

test('rejects mismatched expected session id during handshake', async () => {
  resetSockets();
  const connecting = connectBrowserSmpWebSocketTransport({
    url: 'wss://smp.example/ws',
    expectedSessionId: filled(32, 9),
    WebSocketImpl: FakeWebSocket,
    timeoutMs: 1000
  });
  const socket = FakeWebSocket.instances[0];
  socket.open();
  await nextTurn();
  socket.message(padBlock(encodeServerHandshake({
    minVersion: 3,
    maxVersion: 4,
    sessionId: filled(32, 8)
  })).buffer);
  await assert.rejects(connecting, /session id did not match/);
});
