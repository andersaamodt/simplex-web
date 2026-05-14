// SPDX-License-Identifier: AGPL-3.0-only
//
// Native SMP TLS relay for browser WebSocket clients.
//
// Existing public SimpleX SMP servers speak native SMP over TLS with ALPN
// `smp/1`; browsers cannot open that socket shape directly.  This relay is a
// narrow byte gateway: it accepts WebSocket binary frames from the browser,
// opens the native TLS SMP connection, normalizes the server handshake for the
// browser profile, and then forwards only exact 16384-byte SMP transport blocks.
//
// It is not the removed SimpleX Chat command bridge.  It does not accept chat
// plaintext, does not call the SimpleX Chat API, and does not know how to form a
// SimpleX message.  Message bodies are already encrypted by the browser agent
// before they reach this process.

import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { createHash, randomBytes } from 'node:crypto';
import {
  SMP_BLOCK_SIZE,
  encodeServerHandshake,
  padBlock,
  unpadBlock
} from './browser-smp-core.mjs';

export class BrowserSmpNativeTlsRelayError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSmpNativeTlsRelayError';
    this.code = code;
  }
}

function relayError(code, message) {
  return new BrowserSmpNativeTlsRelayError(code, message);
}

function fail(code, message) {
  throw relayError(code, message);
}

function text(value) {
  return String(value == null ? '' : value).trim();
}

function safePort(value, fallback = 5223) {
  var port = Number(value || fallback);
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail('SMP_RELAY_CONFIG', 'target port is invalid');
  return port;
}

function timingSafeTextEqual(a, b) {
  var left = Buffer.from(String(a || ''));
  var right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return cryptoTimingSafeEqual(left, right);
}

function cryptoTimingSafeEqual(left, right) {
  var diff = 0;
  for (var i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

function acceptKey(key) {
  return createHash('sha1')
    .update(String(key || '') + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}

function encodeServerFrame(payload) {
  var body = Buffer.from(payload);
  if (body.length < 126) return Buffer.concat([Buffer.from([0x82, body.length]), body]);
  if (body.length <= 0xffff) {
    var header16 = Buffer.alloc(4);
    header16[0] = 0x82;
    header16[1] = 126;
    header16.writeUInt16BE(body.length, 2);
    return Buffer.concat([header16, body]);
  }
  var header64 = Buffer.alloc(10);
  header64[0] = 0x82;
  header64[1] = 127;
  header64.writeBigUInt64BE(BigInt(body.length), 2);
  return Buffer.concat([header64, body]);
}

function encodeCloseFrame(code = 1000, reason = '') {
  var body = Buffer.alloc(2 + Buffer.byteLength(reason));
  body.writeUInt16BE(code, 0);
  body.write(String(reason), 2);
  var header = Buffer.from([0x88, body.length]);
  return Buffer.concat([header, body]);
}

function decodeClientFrame(buffer) {
  if (buffer.length < 2) return null;
  var first = buffer[0];
  var opcode = first & 0x0f;
  var final = (first & 0x80) !== 0;
  var masked = (buffer[1] & 0x80) !== 0;
  var length = buffer[1] & 0x7f;
  var offset = 2;
  if (length === 126) {
    if (buffer.length < offset + 2) return null;
    length = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    if (buffer.length < offset + 8) return null;
    var wide = buffer.readBigUInt64BE(offset);
    if (wide > BigInt(Number.MAX_SAFE_INTEGER)) fail('SMP_RELAY_WS_FRAME', 'WebSocket frame is too large');
    length = Number(wide);
    offset += 8;
  }
  if (!masked) fail('SMP_RELAY_WS_FRAME', 'client WebSocket frames must be masked');
  if (buffer.length < offset + 4 + length) return null;
  var mask = buffer.subarray(offset, offset + 4);
  offset += 4;
  var payload = Buffer.from(buffer.subarray(offset, offset + length));
  for (var i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
  return { final, opcode, payload, rest: buffer.subarray(offset + length) };
}

function nativePayloadFromBlock(block) {
  var input = Buffer.from(block);
  if (input.length !== SMP_BLOCK_SIZE) fail('SMP_RELAY_HANDSHAKE', 'native server handshake has the wrong size');
  var nativeLength = input.readUInt16BE(0);
  if (nativeLength < 5 || nativeLength > input.length - 2) fail('SMP_RELAY_HANDSHAKE', 'native server handshake length is invalid');
  return input.subarray(2, 2 + nativeLength);
}

function browserBlockFromNative(block) {
  return padBlock(nativePayloadFromBlock(block), SMP_BLOCK_SIZE);
}

function nativeBlockFromBrowser(block) {
  var body = unpadBlock(block, SMP_BLOCK_SIZE);
  var out = Buffer.alloc(SMP_BLOCK_SIZE);
  out.writeUInt16BE(body.length, 0);
  out.set(body, 2);
  return out;
}

function parseNativeServerHandshake(block) {
  var body = nativePayloadFromBlock(block);
  var offset = 0;
  var minVersion = (body[offset] << 8) | body[offset + 1];
  offset += 2;
  var maxVersion = (body[offset] << 8) | body[offset + 1];
  offset += 2;
  var sessionLength = body[offset];
  offset += 1;
  if (offset + sessionLength > body.length) fail('SMP_RELAY_HANDSHAKE', 'native server session id is truncated');
  var sessionId = body.slice(offset, offset + sessionLength);
  offset += sessionLength;
  var nativeIdentity = body.slice(offset);
  if (!sessionId.length) fail('SMP_RELAY_HANDSHAKE', 'native server session id is empty');
  if (minVersion > maxVersion) fail('SMP_RELAY_HANDSHAKE', 'native server version range is invalid');
  return { minVersion, maxVersion, sessionId, nativeIdentity };
}

function websocketAllowed(request, options) {
  var origin = text(request.headers.origin);
  var allowedOrigins = options.allowedOrigins || [];
  if (!allowedOrigins.length) return true;
  return allowedOrigins.some((allowed) => timingSafeTextEqual(origin, allowed));
}

function requestedProtocol(request) {
  return String(request.headers['sec-websocket-protocol'] || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function completeWebSocketUpgrade(request, socket, protocol) {
  var key = request.headers['sec-websocket-key'];
  if (!key) fail('SMP_RELAY_WS_UPGRADE', 'missing WebSocket key');
  var response = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    'Sec-WebSocket-Accept: ' + acceptKey(key)
  ];
  if (protocol) response.push('Sec-WebSocket-Protocol: ' + protocol);
  response.push('', '');
  socket.write(response.join('\r\n'));
}

function connectNativeTarget(options) {
  if (typeof options.connectNative === 'function') return options.connectNative(options);
  var target = options.target || {};
  var host = text(target.host || options.targetHost);
  if (!host) fail('SMP_RELAY_CONFIG', 'target host is required');
  var port = safePort(target.port || options.targetPort);
  return tls.connect({
    host,
    port,
    servername: text(target.servername || options.targetServername || host),
    ALPNProtocols: ['smp/1'],
    rejectUnauthorized: options.rejectUnauthorized !== false
  });
}

function readExact(stream, length, timeoutMs) {
  return new Promise((resolve, reject) => {
    var chunks = [];
    var total = 0;
    var timer = setTimeout(() => cleanup(reject, relayError('SMP_RELAY_TIMEOUT', 'timed out reading native SMP block')), timeoutMs);
    function cleanup(done, value) {
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('error', onError);
      stream.off('close', onClose);
      done(value);
    }
    function onError(error) {
      cleanup(reject, error);
    }
    function onClose() {
      cleanup(reject, relayError('SMP_RELAY_CLOSED', 'native SMP connection closed'));
    }
    function onData(chunk) {
      chunks.push(chunk);
      total += chunk.length;
      if (total < length) return;
      var joined = Buffer.concat(chunks, total);
      var extra = joined.subarray(length);
      cleanup(resolve, joined.subarray(0, length));
      if (extra.length) stream.unshift(extra);
    }
    stream.on('data', onData);
    stream.once('error', onError);
    stream.once('close', onClose);
    if (typeof stream.resume === 'function') stream.resume();
  });
}

async function startNativeConnection(wsSocket, nativeStream, options) {
  var timeoutMs = Math.max(1000, Number(options.timeoutMs || 15000) || 15000);
  await new Promise((resolve) => setTimeout(resolve, 50));
  var nativeHandshakeBlock = await readExact(nativeStream, SMP_BLOCK_SIZE, timeoutMs);
  var nativeHandshake = parseNativeServerHandshake(nativeHandshakeBlock);
  var maxVersion = Math.min(Number(options.maxVersion || 15), nativeHandshake.maxVersion);
  var browserHandshake = padBlock(encodeServerHandshake({
    minVersion: nativeHandshake.minVersion,
    maxVersion,
    sessionId: nativeHandshake.sessionId
  }), SMP_BLOCK_SIZE);
  await new Promise((resolve) => setImmediate(resolve));
  wsSocket.write(encodeServerFrame(browserHandshake));
  return nativeHandshake;
}

function closePair(wsSocket, nativeStream, code = 1000, reason = '') {
  try {
    if (!wsSocket.destroyed) wsSocket.write(encodeCloseFrame(code, reason));
  } catch (_error) {}
  try { wsSocket.destroy(); } catch (_error) {}
  try { nativeStream.destroy(); } catch (_error) {}
}

export function handleSmpNativeTlsRelayUpgrade(request, socket, head, options = {}) {
  var path = text(options.path || '/simplex/smp');
  var url = new URL(request.url || '/', 'http://127.0.0.1');
  if (url.pathname !== path) return false;
  if (head && head.length) return false;
  if (!websocketAllowed(request, options)) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return true;
  }
  var protocols = requestedProtocol(request);
  var protocol = protocols.includes('simplex-smp.v4.ws') ? 'simplex-smp.v4.ws' : '';
  if (!protocol) {
    socket.write('HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nSec-WebSocket-Protocol: simplex-smp.v4.ws\r\n\r\n');
    socket.destroy();
    return true;
  }

  var nativeStream;
  try {
    nativeStream = connectNativeTarget(options);
    completeWebSocketUpgrade(request, socket, protocol);
  } catch (error) {
    socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return true;
  }

  var started = startNativeConnection(socket, nativeStream, options).then(() => {
    nativeStream.on('data', (chunk) => {
      if (chunk.length !== SMP_BLOCK_SIZE) return closePair(socket, nativeStream, 1011, 'bad native SMP block');
      socket.write(encodeServerFrame(browserBlockFromNative(chunk)));
    });
  }).catch(() => {
    closePair(socket, nativeStream, 1011, 'native SMP unavailable');
  });
  var wsBuffer = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    wsBuffer = Buffer.concat([wsBuffer, chunk]);
    try {
      for (;;) {
        var frame = decodeClientFrame(wsBuffer);
        if (!frame) return;
        wsBuffer = frame.rest;
        if (frame.opcode === 0x8) return closePair(socket, nativeStream);
        if (frame.opcode === 0x9) {
          socket.write(Buffer.concat([Buffer.from([0x8a, frame.payload.length]), frame.payload]));
          continue;
        }
        if (!frame.final || frame.opcode !== 0x2 || frame.payload.length !== SMP_BLOCK_SIZE) {
          return closePair(socket, nativeStream, 1003, 'binary SMP blocks only');
        }
        const payload = frame.payload;
        started.then(() => {
          if (!nativeStream.destroyed) nativeStream.write(nativeBlockFromBrowser(payload));
        });
      }
    } catch (_error) {
      closePair(socket, nativeStream, 1002, 'bad WebSocket frame');
    }
  });
  nativeStream.on('error', () => closePair(socket, nativeStream, 1011, 'native SMP error'));
  nativeStream.on('close', () => closePair(socket, nativeStream));
  socket.on('error', () => closePair(socket, nativeStream));
  socket.on('close', () => closePair(socket, nativeStream));
  return true;
}

export function createSmpNativeTlsRelayServer(options = {}) {
  var server = http.createServer((request, response) => {
    if (request.url === '/healthz') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('ok\n');
      return;
    }
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('not found\n');
  });
  server.on('upgrade', (request, socket, head) => {
    if (!handleSmpNativeTlsRelayUpgrade(request, socket, head, options)) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
    }
  });
  return server;
}

function envList(name) {
  return text(process.env[name]).split(',').map((item) => item.trim()).filter(Boolean);
}

export function relayOptionsFromEnv(env = process.env) {
  return {
    path: text(env.SIMPLEX_WEB_SMP_RELAY_PATH) || '/simplex/smp',
    target: {
      host: text(env.SIMPLEX_WEB_SMP_TARGET_HOST),
      port: safePort(env.SIMPLEX_WEB_SMP_TARGET_PORT || 5223),
      servername: text(env.SIMPLEX_WEB_SMP_TARGET_SERVERNAME || env.SIMPLEX_WEB_SMP_TARGET_HOST)
    },
    allowedOrigins: envList('SIMPLEX_WEB_SMP_RELAY_ALLOWED_ORIGINS'),
    rejectUnauthorized: text(env.SIMPLEX_WEB_SMP_TARGET_REJECT_UNAUTHORIZED || 'true') !== 'false',
    timeoutMs: Number(env.SIMPLEX_WEB_SMP_RELAY_TIMEOUT_MS || 15000) || 15000,
    maxVersion: Number(env.SIMPLEX_WEB_SMP_RELAY_MAX_VERSION || 15) || 15
  };
}

export function startSmpNativeTlsRelayFromEnv(env = process.env) {
  var options = relayOptionsFromEnv(env);
  var host = text(env.SIMPLEX_WEB_SMP_RELAY_HOST) || '127.0.0.1';
  var port = safePort(env.SIMPLEX_WEB_SMP_RELAY_PORT || 8097);
  var server = createSmpNativeTlsRelayServer(options);
  server.listen(port, host);
  return { server, host, port, options };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  var started = startSmpNativeTlsRelayFromEnv();
  // Keep startup output deliberately small so service managers can scrape it.
  process.stdout.write(`simplex-web SMP relay listening on ${started.host}:${started.port}${started.options.path}\n`);
}

export default {
  BrowserSmpNativeTlsRelayError,
  createSmpNativeTlsRelayServer,
  handleSmpNativeTlsRelayUpgrade,
  relayOptionsFromEnv,
  startSmpNativeTlsRelayFromEnv
};
