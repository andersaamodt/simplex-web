import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';

import {
  SMP_BLOCK_SIZE,
  asciiBytes,
  decodeTransportBlock,
  encodeBrokerMessage,
  encodeServerHandshake,
  encodeSignedTransmission,
  encodeTransportBlock,
  equalBytes,
  padBlock,
  parseClientHandshake,
  unpadBlock
} from '../src/browser-smp-core.mjs';
import { connectBrowserSmpWebSocketTransport } from '../src/browser-smp-websocket-transport.mjs';
import { createSmpNativeTlsRelayServer } from '../src/browser-smp-native-tls-relay.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function closeServer(server) {
  return new Promise((resolve) => {
    try {
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      server.close(() => resolve());
      setTimeout(resolve, 200).unref();
    } catch (_error) {
      resolve();
    }
  });
}

const readRemainders = new WeakMap();

function readBlock(socket) {
  return new Promise((resolve, reject) => {
    let buffer = readRemainders.get(socket) || Buffer.alloc(0);
    readRemainders.delete(socket);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('timed out reading test SMP block'));
    }, 5000);
    function cleanup() {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    }
    function onError(error) {
      cleanup();
      reject(error);
    }
    function onClose() {
      cleanup();
      reject(new Error('socket closed'));
    }
    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < SMP_BLOCK_SIZE) return;
      const block = buffer.subarray(0, SMP_BLOCK_SIZE);
      const extra = buffer.subarray(SMP_BLOCK_SIZE);
      cleanup();
      if (extra.length) readRemainders.set(socket, extra);
      resolve(new Uint8Array(block));
    }
    if (buffer.length >= SMP_BLOCK_SIZE) return onData(Buffer.alloc(0));
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
  });
}

async function withNativeServer(options, fn) {
  const sessionId = filled(32, 61);
  const captured = {};
  const sockets = new Set();
  const native = net.createServer(async (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    try {
      const handshake = new Uint8Array([
        ...encodeServerHandshake({ minVersion: 6, maxVersion: 18, sessionId }),
        ...filled(16, 201)
      ]);
      const nativeHandshake = options.nativeLengthPrefix === true
        ? new Uint8Array([handshake.length >> 8, handshake.length & 0xff, ...handshake])
        : handshake;
      socket.write(Buffer.from(padBlock(nativeHandshake, SMP_BLOCK_SIZE)));
      captured.clientHandshake = parseClientHandshake(unpadBlock(await readBlock(socket)));
      const txBlock = await readBlock(socket);
      const [tx] = decodeTransportBlock(6, txBlock);
      captured.command = tx;
      const response = encodeSignedTransmission(6, sessionId, {
        signature: new Uint8Array(),
        corrId: tx.corrId,
        queueId: tx.queueId,
        commandBytes: encodeBrokerMessage(6, { type: 'PONG' })
      });
      socket.write(Buffer.from(encodeTransportBlock(6, [response])));
    } catch (error) {
      socket.destroy(error);
    }
  });
  await new Promise((resolve) => native.listen(0, '127.0.0.1', resolve));
  try {
    await fn({ native, sessionId, captured });
  } finally {
    for (const socket of sockets) socket.destroy();
    await closeServer(native);
  }
}

async function withRelay(native, fn) {
  const address = native.address();
  const relay = createSmpNativeTlsRelayServer({
    path: '/simplex/smp',
    target: { host: '127.0.0.1', port: address.port },
    connectNative(options) {
      return net.connect(options.target.port, options.target.host);
    },
    timeoutMs: 5000
  });
  const sockets = new Set();
  relay.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve) => relay.listen(0, '127.0.0.1', resolve));
  try {
    const relayAddress = relay.address();
    await fn(`ws://127.0.0.1:${relayAddress.port}/simplex/smp`);
  } finally {
    for (const socket of sockets) socket.destroy();
    await closeServer(relay);
  }
}

async function assertRelayForwardsNativeBlocks(options = {}) {
  await withNativeServer(options, async ({ native, sessionId, captured }) => {
    await withRelay(native, async (url) => {
      const transport = await connectBrowserSmpWebSocketTransport({
        url,
        keyHash: filled(32, 44),
        timeoutMs: 5000
      });
      assert.equal(transport.version, 6);
      assert.equal(equalBytes(transport.sessionId, sessionId), true);

      const corrId = asciiBytes('relay-ping');
      transport.sendSignedTransmissions([
        encodeSignedTransmission(6, sessionId, {
          signature: new Uint8Array(),
          corrId,
          queueId: new Uint8Array(),
          command: { type: 'PING' }
        })
      ]);
      const [response] = await transport.receiveSignedTransmissions({ kind: 'broker', timeoutMs: 5000 });
      assert.equal(response.message.type, 'PONG');
      assert.equal(equalBytes(response.corrId, corrId), true);
      assert.equal(captured.clientHandshake.version, 6);
      assert.equal(equalBytes(captured.clientHandshake.keyHash, filled(32, 44)), true);
      assert.equal(captured.command.command.type, 'PING');
      transport.close();
    });
  });
}

test('native TLS relay normalizes native handshake and forwards SMP blocks', async () => {
  await assertRelayForwardsNativeBlocks();
});

test('native TLS relay accepts public-server native length-prefixed handshake', async () => {
  await assertRelayForwardsNativeBlocks({ nativeLengthPrefix: true });
});

test('native TLS relay rejects non-binary WebSocket clients', async () => {
  await withNativeServer({}, async ({ native }) => {
    await withRelay(native, async (url) => {
      const parsed = new URL(url);
      const request = http.request({
        host: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        headers: {
          Connection: 'Upgrade',
          Upgrade: 'websocket',
          'Sec-WebSocket-Key': 'SGVsbG9Xb3JsZEtleQ==',
          'Sec-WebSocket-Version': '13',
          'Sec-WebSocket-Protocol': 'wrong-protocol'
        }
      });
      const status = await new Promise((resolve) => {
        request.on('response', (response) => resolve(response.statusCode));
        request.on('upgrade', () => resolve(101));
        request.end();
      });
      assert.equal(status, 426);
    });
  });
});
