// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser-native SMP-over-WebSocket transport profile.
//
// Browsers cannot open raw TCP sockets or inspect TLS channel-binding data from
// JavaScript, so this is not the native simplexmq TCP/TLS transport. It is a
// small browser transport profile for SMP servers that expose binary WebSocket
// frames. Each WebSocket message carries exactly one padded SMP transport block.
//
// This module never talks to a plaintext compatibility API and never forwards
// chat plaintext through a web server. Callers pass already encoded/signed SMP
// transmissions, and message bodies should already be encrypted by the agent
// layer before they reach `SEND`.

import {
  SMP_BLOCK_SIZE,
  chooseCompatibleVersion,
  decodeTransportBlock,
  encodeClientHandshake,
  encodeTransportBlock,
  equalBytes,
  parseServerHandshake,
  padBlock,
  toBytes,
  unpadBlock
} from './browser-smp-core.mjs';

export class BrowserSmpWebSocketTransportError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSmpWebSocketTransportError';
    this.code = code;
  }
}

function transportError(code, message) {
  return new BrowserSmpWebSocketTransportError(code, message);
}

function fail(code, message) {
  throw transportError(code, message);
}

function isLoopbackHost(hostname) {
  var host = String(hostname || '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

export function normalizeSmpWebSocketUrl(value, options = {}) {
  var raw = String(value || '').trim();
  if (!raw) fail('SIMPLEX_SMP_WS_CONFIG', 'SMP WebSocket URL is required');
  var parsed;
  try {
    parsed = new URL(raw, globalThis.location && globalThis.location.href || 'http://127.0.0.1/');
  } catch (_error) {
    fail('SIMPLEX_SMP_WS_CONFIG', 'SMP WebSocket URL is invalid');
  }
  if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
    fail('SIMPLEX_SMP_WS_CONFIG', 'SMP WebSocket URL must use ws:// or wss://');
  }
  if (parsed.protocol === 'ws:' && !isLoopbackHost(parsed.hostname) && options.allowInsecureRemote !== true) {
    fail('SIMPLEX_SMP_WS_SECURITY', 'remote SMP WebSocket transports must use wss://');
  }
  return parsed.href;
}

function eventTargetOn(target, name, handler) {
  if (typeof target.addEventListener === 'function') {
    target.addEventListener(name, handler);
    return () => target.removeEventListener(name, handler);
  }
  var prop = 'on' + name;
  var previous = target[prop];
  target[prop] = function (event) {
    if (typeof previous === 'function') previous.call(target, event);
    handler.call(target, event);
  };
  return () => {
    if (target[prop] === handler) target[prop] = previous;
  };
}

function socketReadyState(socket) {
  return Number(socket && socket.readyState);
}

function isSocketOpen(socket) {
  return socketReadyState(socket) === 1;
}

function withTimeout(promise, timeoutMs, code, message) {
  var timeout = Math.max(1, Math.floor(Number(timeoutMs || 15000) || 15000));
  var timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(transportError(code, message)), timeout);
    })
  ]).finally(() => clearTimeout(timer));
}

async function frameToBytes(frame) {
  // Browser and Node-compatible WebSocket implementations expose message data
  // through a prototype getter, not always as an own property. Use `in` so the
  // real browser shape and the test harness shape both take the same path.
  var data = frame && typeof frame === 'object' && 'data' in frame ? frame.data : frame;
  if (data instanceof ArrayBuffer) return new Uint8Array(data.slice(0));
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  }
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  fail('SIMPLEX_SMP_WS_TEXT_FRAME', 'SMP WebSocket transport received a non-binary frame');
}

function createFrameQueue(socket, options = {}) {
  var frames = [];
  var waiters = [];
  var closed = false;
  var closeError = null;
  var cleanups = [];

  function flushError(error) {
    closeError = error;
    while (waiters.length) waiters.shift().reject(error);
  }

  cleanups.push(eventTargetOn(socket, 'message', async (event) => {
    try {
      var bytes = await frameToBytes(event);
      if (bytes.length !== SMP_BLOCK_SIZE) {
        throw transportError('SIMPLEX_SMP_WS_BAD_BLOCK', 'SMP WebSocket frame must be exactly one 16384-byte block');
      }
      if (waiters.length) waiters.shift().resolve(bytes);
      else frames.push(bytes);
    } catch (error) {
      flushError(error);
      if (options.closeOnProtocolError !== false && typeof socket.close === 'function') socket.close();
    }
  }));
  cleanups.push(eventTargetOn(socket, 'error', () => {
    flushError(transportError('SIMPLEX_SMP_WS_SOCKET', 'SMP WebSocket transport error'));
  }));
  cleanups.push(eventTargetOn(socket, 'close', () => {
    closed = true;
    flushError(transportError('SIMPLEX_SMP_WS_CLOSED', 'SMP WebSocket transport closed'));
  }));

  return {
    receive(timeoutMs) {
      if (frames.length) return Promise.resolve(frames.shift());
      if (closeError) return Promise.reject(closeError);
      if (closed) return Promise.reject(transportError('SIMPLEX_SMP_WS_CLOSED', 'SMP WebSocket transport closed'));
      return withTimeout(new Promise((resolve, reject) => {
        waiters.push({ resolve, reject });
      }), timeoutMs, 'SIMPLEX_SMP_WS_TIMEOUT', 'timed out waiting for SMP WebSocket frame');
    },
    dispose() {
      for (var cleanup of cleanups.splice(0)) cleanup();
      frames = [];
      while (waiters.length) waiters.shift().reject(transportError('SIMPLEX_SMP_WS_CLOSED', 'SMP WebSocket transport closed'));
    }
  };
}

function waitForOpen(socket, timeoutMs) {
  if (isSocketOpen(socket)) return Promise.resolve();
  if (socketReadyState(socket) > 1) {
    return Promise.reject(transportError('SIMPLEX_SMP_WS_CLOSED', 'SMP WebSocket transport closed before opening'));
  }
  return withTimeout(new Promise((resolve, reject) => {
    var cleanups = [];
    function done(fn, value) {
      for (var cleanup of cleanups.splice(0)) cleanup();
      fn(value);
    }
    cleanups.push(eventTargetOn(socket, 'open', () => done(resolve)));
    cleanups.push(eventTargetOn(socket, 'error', () => done(reject, transportError('SIMPLEX_SMP_WS_SOCKET', 'SMP WebSocket transport failed to open'))));
    cleanups.push(eventTargetOn(socket, 'close', () => done(reject, transportError('SIMPLEX_SMP_WS_CLOSED', 'SMP WebSocket transport closed before opening'))));
  }), timeoutMs, 'SIMPLEX_SMP_WS_TIMEOUT', 'timed out opening SMP WebSocket transport');
}

function socketSend(socket, block) {
  if (!isSocketOpen(socket)) fail('SIMPLEX_SMP_WS_CLOSED', 'SMP WebSocket transport is not open');
  try {
    socket.send(block);
  } catch (error) {
    throw transportError('SIMPLEX_SMP_WS_SEND', error && error.message ? error.message : 'SMP WebSocket send failed');
  }
}

export async function connectBrowserSmpWebSocketTransport(options = {}) {
  var WebSocketImpl = options.WebSocketImpl || globalThis.WebSocket;
  if (typeof WebSocketImpl !== 'function') {
    fail('SIMPLEX_SMP_WS_CONFIG', 'WebSocket is not available');
  }
  var url = normalizeSmpWebSocketUrl(options.url, options);
  var protocols = options.protocols || ['simplex-smp.v4.ws'];
  var socket = new WebSocketImpl(url, protocols);
  if ('binaryType' in socket) socket.binaryType = 'arraybuffer';
  await waitForOpen(socket, options.openTimeoutMs || options.timeoutMs);

  var queue = createFrameQueue(socket, options);
  var serverBlock = await queue.receive(options.handshakeTimeoutMs || options.timeoutMs);
  var serverHandshake = parseServerHandshake(unpadBlock(serverBlock));
  if (options.expectedSessionId && !equalBytes(serverHandshake.sessionId, options.expectedSessionId)) {
    socket.close();
    fail('SIMPLEX_SMP_WS_SESSION', 'SMP WebSocket server session id did not match expected value');
  }
  var version = chooseCompatibleVersion(serverHandshake, {
    minVersion: options.minVersion || 3,
    maxVersion: options.maxVersion || 15
  });
  var keyHash = toBytes(options.keyHash || new Uint8Array(), 'SMP server identity hash');
  socketSend(socket, padBlock(encodeClientHandshake({ version, keyHash })));

  return {
    profile: 'simplex-smp-websocket-browser-v1',
    url,
    version,
    sessionId: serverHandshake.sessionId,
    keyHash,
    security: {
      plaintextBridge: false,
      browserNativeProtocol: true,
      rawTcp: false,
      tlsUniqueChannelBindingFromJs: false,
      serverIdentityPinnedByJs: false,
      binarySmpBlocksOnly: true
    },
    getStatus() {
      return {
        connected: isSocketOpen(socket),
        version,
        profile: 'simplex-smp-websocket-browser-v1'
      };
    },
    sendSignedTransmissions(transmissions) {
      socketSend(socket, encodeTransportBlock(version, transmissions));
    },
    async receiveSignedTransmissions(parseOptions = {}) {
      var block = await queue.receive(parseOptions.timeoutMs || options.timeoutMs);
      return decodeTransportBlock(version, block, {
        sessionId: serverHandshake.sessionId,
        ...parseOptions
      });
    },
    close(code, reason) {
      queue.dispose();
      if (typeof socket.close === 'function' && socketReadyState(socket) < 2) {
        socket.close(code, reason);
      }
    },
    socket
  };
}

export default {
  BrowserSmpWebSocketTransportError,
  connectBrowserSmpWebSocketTransport,
  normalizeSmpWebSocketUrl
};
