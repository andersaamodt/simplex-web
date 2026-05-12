// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser double-ratchet state machine.
//
// This is the browser-owned ratchet layer used by simplex-web. It follows the
// standard DH-ratchet shape: root-key KDF, sending/receiving chain KDFs,
// per-message AEAD keys, skipped-message keys, and explicit counters. The wire
// header is intentionally small JSON-friendly data so higher SimpleX envelope
// code can carry it as bytes without relying on a daemon.

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  asciiBytes,
  concatBytes,
  decodeBase64Url,
  encodeBase64Url,
  encryptAesGcm,
  generateX25519KeyPair,
  randomBytes32,
  randomNonce24,
  toBytes,
  utf8Bytes,
  utf8Text,
  x25519SharedSecret,
  decryptAesGcm
} from './browser-smp-core.mjs';

export const SIMPLEX_RATCHET_VERSION = 1;
export const SIMPLEX_RATCHET_MAX_SKIP = 2000;

export class BrowserSimplexRatchetError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSimplexRatchetError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserSimplexRatchetError(code, message);
}

function kdf(input, salt, info, length = 32) {
  return hkdf(sha256, toBytes(input, 'KDF input'), toBytes(salt || new Uint8Array(32), 'KDF salt'), asciiBytes(info), length);
}

function split64(bytes, label) {
  var out = toBytes(bytes, label);
  if (out.length !== 64) fail('SIMPLEX_RATCHET_KDF', label + ' must produce 64 bytes');
  return [out.slice(0, 32), out.slice(32)];
}

function deriveRoot(rootKey, dhSecret) {
  var parts = split64(kdf(dhSecret, rootKey, 'simplex-web ratchet root', 64), 'root KDF');
  return { rootKey: parts[0], chainKey: parts[1] };
}

function deriveMessageKey(chainKey) {
  var parts = split64(kdf(chainKey, new Uint8Array(32), 'simplex-web ratchet chain', 64), 'chain KDF');
  return { nextChainKey: parts[0], messageKey: parts[1] };
}

function normalizeState(state) {
  var s = state && typeof state === 'object' ? state : {};
  if (!s.rootKey) fail('SIMPLEX_RATCHET_STATE', 'ratchet root key is missing');
  if (!s.ownDhKey) fail('SIMPLEX_RATCHET_STATE', 'own DH key is missing');
  return {
    version: SIMPLEX_RATCHET_VERSION,
    rootKey: toBytes(s.rootKey, 'root key'),
    ownDhKey: s.ownDhKey,
    remoteDhPublicKey: s.remoteDhPublicKey ? toBytes(s.remoteDhPublicKey, 'remote DH public key') : null,
    sendingChainKey: s.sendingChainKey ? toBytes(s.sendingChainKey, 'sending chain key') : null,
    receivingChainKey: s.receivingChainKey ? toBytes(s.receivingChainKey, 'receiving chain key') : null,
    sendCount: Math.max(0, Math.floor(Number(s.sendCount || 0) || 0)),
    receiveCount: Math.max(0, Math.floor(Number(s.receiveCount || 0) || 0)),
    previousSendCount: Math.max(0, Math.floor(Number(s.previousSendCount || 0) || 0)),
    skipped: Array.isArray(s.skipped) ? s.skipped.slice(-SIMPLEX_RATCHET_MAX_SKIP) : []
  };
}

export function createRatchetState(options = {}) {
  var ownDhKey = options.ownDhKey || generateX25519KeyPair(options.ownDhSeed);
  var rootKey = options.rootKey ? toBytes(options.rootKey, 'root key') : randomBytes32();
  var remoteDhPublicKey = options.remoteDhPublicKey ? toBytes(options.remoteDhPublicKey, 'remote DH public key') : null;
  var sendingChainKey = options.sendingChainKey ? toBytes(options.sendingChainKey, 'sending chain key') : null;
  var receivingChainKey = options.receivingChainKey ? toBytes(options.receivingChainKey, 'receiving chain key') : null;
  if (remoteDhPublicKey && !sendingChainKey && options.initializeSending !== false) {
    var derived = deriveRoot(rootKey, x25519SharedSecret(ownDhKey.secretKey, remoteDhPublicKey));
    rootKey = derived.rootKey;
    sendingChainKey = derived.chainKey;
  }
  return normalizeState({ rootKey, ownDhKey, remoteDhPublicKey, sendingChainKey, receivingChainKey });
}

function headerBytes(header) {
  return utf8Bytes(JSON.stringify({
    v: SIMPLEX_RATCHET_VERSION,
    dh: encodeBase64Url(header.dh),
    pn: header.previousSendCount,
    n: header.messageNumber
  }));
}

export function parseRatchetHeader(bytes) {
  var parsed;
  try {
    parsed = JSON.parse(utf8Text(bytes));
  } catch (_error) {
    fail('SIMPLEX_RATCHET_HEADER', 'ratchet header is not valid JSON');
  }
  if (!parsed || parsed.v !== SIMPLEX_RATCHET_VERSION) fail('SIMPLEX_RATCHET_HEADER', 'ratchet header version is unsupported');
  return {
    dh: decodeBase64Url(parsed.dh, 'ratchet DH key'),
    previousSendCount: Math.max(0, Math.floor(Number(parsed.pn || 0) || 0)),
    messageNumber: Math.max(0, Math.floor(Number(parsed.n || 0) || 0))
  };
}

function advanceSending(state) {
  if (!state.sendingChainKey) fail('SIMPLEX_RATCHET_STATE', 'sending chain is not initialized');
  var derived = deriveMessageKey(state.sendingChainKey);
  state.sendingChainKey = derived.nextChainKey;
  state.sendCount += 1;
  return derived.messageKey;
}

function advanceReceiving(state) {
  if (!state.receivingChainKey) fail('SIMPLEX_RATCHET_STATE', 'receiving chain is not initialized');
  var derived = deriveMessageKey(state.receivingChainKey);
  state.receivingChainKey = derived.nextChainKey;
  state.receiveCount += 1;
  return derived.messageKey;
}

function skippedKeyId(dh, n) {
  return encodeBase64Url(dh) + ':' + String(n);
}

function saveSkipped(state, dh, n, key) {
  state.skipped.push({ id: skippedKeyId(dh, n), key });
  if (state.skipped.length > SIMPLEX_RATCHET_MAX_SKIP) state.skipped.shift();
}

function takeSkipped(state, dh, n) {
  var id = skippedKeyId(dh, n);
  var index = state.skipped.findIndex((item) => item.id === id);
  if (index < 0) return null;
  var item = state.skipped.splice(index, 1)[0];
  return item.key;
}

function ratchetReceiveStep(state, remoteDh) {
  state.previousSendCount = state.sendCount;
  state.sendCount = 0;
  state.receiveCount = 0;
  state.remoteDhPublicKey = remoteDh;
  var receive = deriveRoot(state.rootKey, x25519SharedSecret(state.ownDhKey.secretKey, remoteDh));
  state.rootKey = receive.rootKey;
  state.receivingChainKey = receive.chainKey;
  state.ownDhKey = generateX25519KeyPair();
  var send = deriveRoot(state.rootKey, x25519SharedSecret(state.ownDhKey.secretKey, remoteDh));
  state.rootKey = send.rootKey;
  state.sendingChainKey = send.chainKey;
}

export function encryptRatchetMessage(stateInput, plaintext, options = {}) {
  var state = normalizeState(stateInput);
  var messageNumber = state.sendCount;
  var messageKey = advanceSending(state);
  var nonce = options.nonce ? toBytes(options.nonce, 'ratchet nonce') : randomNonce24();
  var header = {
    dh: state.ownDhKey.publicKey,
    previousSendCount: state.previousSendCount,
    messageNumber
  };
  var encodedHeader = headerBytes(header);
  var encrypted = encryptAesGcm(messageKey, nonce.slice(0, 12), plaintext, options.paddedLength || Math.max(64, toBytes(plaintext, 'plaintext').length + 2), encodedHeader);
  return {
    state,
    packet: {
      version: SIMPLEX_RATCHET_VERSION,
      header: encodedHeader,
      nonce: nonce.slice(0, 12),
      ciphertext: encrypted.ciphertext,
      tag: encrypted.tag
    }
  };
}

function skipUntil(state, header) {
  if (header.messageNumber - state.receiveCount > SIMPLEX_RATCHET_MAX_SKIP) {
    fail('SIMPLEX_RATCHET_SKIP', 'too many skipped message keys');
  }
  while (state.receiveCount < header.messageNumber) {
    saveSkipped(state, header.dh, state.receiveCount, advanceReceiving(state));
  }
}

export function decryptRatchetMessage(stateInput, packet) {
  var state = normalizeState(stateInput);
  var pkt = packet && typeof packet === 'object' ? packet : {};
  var header = parseRatchetHeader(pkt.header);
  var skipped = takeSkipped(state, header.dh, header.messageNumber);
  var messageKey;
  if (skipped) {
    messageKey = skipped;
  } else {
    if (!state.remoteDhPublicKey || encodeBase64Url(state.remoteDhPublicKey) !== encodeBase64Url(header.dh)) {
      ratchetReceiveStep(state, header.dh);
    }
    skipUntil(state, header);
    messageKey = advanceReceiving(state);
  }
  return {
    state,
    plaintext: decryptAesGcm(messageKey, pkt.nonce, pkt.ciphertext, pkt.tag, pkt.header)
  };
}

export default {
  BrowserSimplexRatchetError,
  SIMPLEX_RATCHET_VERSION,
  createRatchetState,
  decryptRatchetMessage,
  encryptRatchetMessage,
  parseRatchetHeader
};
