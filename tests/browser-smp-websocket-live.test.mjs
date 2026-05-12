import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';

import {
  asciiBytes,
  decodeTransportBlock,
  encodeBrokerMessage,
  encodeServerHandshake,
  encodeSignedTransmission,
  encodeTransportBlock,
  equalBytes,
  parseClientHandshake,
  padBlock,
  unpadBlock
} from '../src/browser-smp-core.mjs';
import { connectBrowserSmpWebSocketTransport } from '../src/browser-smp-websocket-transport.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function defer() {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function acceptKey(key) {
  return createHash('sha1')
    .update(String(key || '') + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}

function encodeServerBinaryFrame(payload) {
  const body = Buffer.from(payload);
  if (body.length < 126) return Buffer.concat([Buffer.from([0x82, body.length]), body]);
  if (body.length <= 0xffff) {
    const header = Buffer.alloc(4);
    header[0] = 0x82;
    header[1] = 126;
    header.writeUInt16BE(body.length, 2);
    return Buffer.concat([header, body]);
  }
  const header = Buffer.alloc(10);
  header[0] = 0x82;
  header[1] = 127;
  header.writeBigUInt64BE(BigInt(body.length), 2);
  return Buffer.concat([header, body]);
}

function tryDecodeClientFrame(buffer) {
  if (buffer.length < 2) return null;
  const opcode = buffer[0] & 0x0f;
  const masked = (buffer[1] & 0x80) !== 0;
  let length = buffer[1] & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < offset + 2) return null;
    length = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    if (buffer.length < offset + 8) return null;
    const big = buffer.readBigUInt64BE(offset);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('client frame is too large');
    length = Number(big);
    offset += 8;
  }
  if (!masked) throw new Error('client WebSocket frames must be masked');
  if (buffer.length < offset + 4 + length) return null;
  const mask = buffer.slice(offset, offset + 4);
  offset += 4;
  const payload = Buffer.from(buffer.slice(offset, offset + length));
  for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
  return {
    opcode,
    payload: new Uint8Array(payload),
    rest: buffer.slice(offset + length)
  };
}

async function withLoopbackSmpWebSocketServer(fn) {
  const sessionId = filled(32, 91);
  const captured = {
    clientHandshake: defer(),
    command: defer()
  };
  const server = http.createServer();
  const sockets = new Set();
  server.on('upgrade', (request, socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    const response = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Accept: ' + acceptKey(request.headers['sec-websocket-key'])
    ];
    if (request.headers['sec-websocket-protocol']) {
      response.push('Sec-WebSocket-Protocol: ' + String(request.headers['sec-websocket-protocol']).split(',')[0].trim());
    }
    response.push('', '');
    socket.write(response.join('\r\n'));

    socket.write(encodeServerBinaryFrame(padBlock(encodeServerHandshake({
      minVersion: 3,
      maxVersion: 4,
      sessionId
    }))));

    let buffer = Buffer.alloc(0);
    let sawHandshake = false;
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        for (;;) {
          const decoded = tryDecodeClientFrame(buffer);
          if (!decoded) return;
          buffer = decoded.rest;
          if (decoded.opcode === 0x8) return;
          assert.equal(decoded.opcode, 0x2);
          if (!sawHandshake) {
            sawHandshake = true;
            captured.clientHandshake.resolve(parseClientHandshake(unpadBlock(decoded.payload)));
            continue;
          }
          const [tx] = decodeTransportBlock(4, decoded.payload);
          captured.command.resolve(tx);
          const broker = encodeSignedTransmission(4, sessionId, {
            signature: new Uint8Array(),
            corrId: tx.corrId,
            queueId: tx.queueId,
            commandBytes: encodeBrokerMessage(4, { type: 'PONG' })
          });
          socket.write(encodeServerBinaryFrame(encodeTransportBlock(4, [broker])));
        }
      } catch (error) {
        captured.clientHandshake.reject(error);
        captured.command.reject(error);
        socket.destroy(error);
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    await fn({
      url: `ws://127.0.0.1:${address.port}/smp`,
      sessionId,
      captured
    });
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}

test('live loopback WebSocket SMP transport handshakes sends and receives binary frames', async () => {
  await withLoopbackSmpWebSocketServer(async ({ url, sessionId, captured }) => {
    const transport = await connectBrowserSmpWebSocketTransport({
      url,
      keyHash: filled(32, 92),
      expectedSessionId: sessionId,
      timeoutMs: 2000
    });
    const handshake = await captured.clientHandshake.promise;
    assert.equal(handshake.version, 4);
    assert.equal(equalBytes(handshake.keyHash, filled(32, 92)), true);

    const tx = encodeSignedTransmission(4, sessionId, {
      signature: new Uint8Array(),
      corrId: asciiBytes('live-1'),
      queueId: new Uint8Array(),
      command: { type: 'PING' }
    });
    transport.sendSignedTransmissions([tx]);
    const command = await captured.command.promise;
    assert.equal(command.command.type, 'PING');
    assert.equal(equalBytes(command.corrId, asciiBytes('live-1')), true);

    const [response] = await transport.receiveSignedTransmissions({ kind: 'broker', timeoutMs: 2000 });
    assert.equal(response.message.type, 'PONG');
    assert.equal(equalBytes(response.corrId, asciiBytes('live-1')), true);
    transport.close();
  });
});
