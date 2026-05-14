// SPDX-License-Identifier: AGPL-3.0-only
//
// Native SimpleX X448 ratchet primitives.
//
// This module follows the upstream simplexmq ratchet shape closely enough for
// browser-side native-agent work:
// - X448 DH ratchet keys
// - HKDF-SHA512 with the upstream SimpleX labels
// - AES-GCM message encryption with encrypted padded headers
// - the non-PQ header form used by current invitation links
//
// It is intentionally separate from `browser-simplex-ratchet.mjs`, which is the
// earlier browser-profile ratchet. Keeping them separate avoids silently
// changing existing browser-profile contacts while native SimpleX interop is
// brought up piece by piece.

import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';

import {
  concatBytes,
  decodePublicKeyDer,
  decodeWord16,
  decodeWord32,
  encodeLargeBytes,
  encodePublicKeyDer,
  encodeSmallBytes,
  encodeWord16,
  encodeWord32,
  generateX448KeyPair,
  padMessage,
  toBytes,
  unpadMessage,
  utf8Bytes,
  x448SharedSecret
} from './browser-smp-core.mjs';

export const SIMPLEX_NATIVE_RATCHET_HEADER_LENGTH = 88;
export const SIMPLEX_NATIVE_RATCHET_VERSION = 2;
export const SIMPLEX_NATIVE_ROOT_INFO = 'SimpleXRootRatchet';
export const SIMPLEX_NATIVE_CHAIN_INFO = 'SimpleXChainRatchet';

export class BrowserSimplexNativeRatchetError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSimplexNativeRatchetError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserSimplexNativeRatchetError(code, message);
}

function safeWord32(value, label) {
  var n = Number(value || 0);
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) fail('SIMPLEX_NATIVE_RATCHET_RANGE', label + ' is invalid');
  return n;
}

function hkdf3(salt, ikm, info) {
  var out = hkdf(sha512, toBytes(salt, 'HKDF salt'), toBytes(ikm, 'HKDF input'), utf8Bytes(info), 96);
  return [out.slice(0, 32), out.slice(32, 64), out.slice(64, 96)];
}

function splitIvs(bytes) {
  var ivs = toBytes(bytes, 'ratchet IV material');
  if (ivs.length !== 32) fail('SIMPLEX_NATIVE_RATCHET_KDF', 'ratchet IV material must be 32 bytes');
  return [ivs.slice(0, 16), ivs.slice(16, 32)];
}

function normalizeX448KeyPair(value, label) {
  var key = value && typeof value === 'object' ? value : {};
  var secretKey = key.secretKey ? toBytes(key.secretKey, label + ' secret key') : null;
  if (!secretKey) fail('SIMPLEX_NATIVE_RATCHET_KEY', label + ' secret key is missing');
  if (secretKey.length !== 56) fail('SIMPLEX_NATIVE_RATCHET_KEY', label + ' secret key must be 56 bytes');
  var publicKey = key.publicKey || key.rawPublicKey || null;
  if (!publicKey && key.publicKeyDer) publicKey = decodePublicKeyDer(key.publicKeyDer).rawPublicKey;
  var publicBytes = publicKey ? toBytes(publicKey, label + ' public key') : generateX448KeyPair(secretKey).publicKey;
  if (publicBytes.length !== 56) fail('SIMPLEX_NATIVE_RATCHET_KEY', label + ' public key must be 56 bytes');
  return { secretKey, publicKey: publicBytes, publicKeyDer: encodePublicKeyDer('X448', publicBytes) };
}

function normalizeX448PublicKey(value, label) {
  if (value && typeof value === 'object') {
    if (value.algorithm && value.algorithm !== 'X448') fail('SIMPLEX_NATIVE_RATCHET_KEY', label + ' must be X448');
    if (value.rawPublicKey) return normalizeX448PublicKey(value.rawPublicKey, label);
    if (value.publicKey) return normalizeX448PublicKey(value.publicKey, label);
    if (value.publicKeyDer) return normalizeX448PublicKey(decodePublicKeyDer(value.publicKeyDer), label);
  }
  var key = toBytes(value, label);
  if (key.length !== 56) {
    var decoded = decodePublicKeyDer(key);
    if (decoded.algorithm !== 'X448') fail('SIMPLEX_NATIVE_RATCHET_KEY', label + ' must be X448');
    return decoded.rawPublicKey;
  }
  return key;
}

function rootKdf(rootKey, remotePublicKey, ownSecretKey) {
  var [nextRoot, chainKey, nextHeaderKey] = hkdf3(
    toBytes(rootKey, 'root key'),
    x448SharedSecret(ownSecretKey, remotePublicKey),
    SIMPLEX_NATIVE_ROOT_INFO
  );
  return { rootKey: nextRoot, chainKey, nextHeaderKey };
}

function chainKdf(chainKey) {
  var [nextChainKey, messageKey, ivMaterial] = hkdf3(
    new Uint8Array(),
    toBytes(chainKey, 'chain key'),
    SIMPLEX_NATIVE_CHAIN_INFO
  );
  var [messageIv, headerIv] = splitIvs(ivMaterial);
  return { nextChainKey, messageKey, messageIv, headerIv };
}

function encryptAead(key, iv, aad, plaintext, paddedLength) {
  var padded = padMessage(plaintext, paddedLength);
  var packet = gcm(toBytes(key, 'AES-GCM key'), toBytes(iv, 'AES-GCM IV'), toBytes(aad, 'AES-GCM associated data')).encrypt(padded);
  return { body: packet.slice(0, packet.length - 16), tag: packet.slice(packet.length - 16) };
}

function decryptAead(key, iv, aad, body, tag) {
  try {
    return unpadMessage(gcm(
      toBytes(key, 'AES-GCM key'),
      toBytes(iv, 'AES-GCM IV'),
      toBytes(aad, 'AES-GCM associated data')
    ).decrypt(concatBytes(body, tag)));
  } catch (_error) {
    fail('SIMPLEX_NATIVE_RATCHET_DECRYPT', 'native ratchet decryption failed');
  }
}

export function createNativeSendingRatchet(options = {}) {
  var init = options.init || {};
  var ownDhKey = normalizeX448KeyPair(options.ownDhKey || generateX448KeyPair(), 'sending DH key');
  var remoteDhPublicKey = normalizeX448PublicKey(options.remoteDhPublicKey, 'remote DH key');
  var derived = rootKdf(init.ratchetKey, remoteDhPublicKey, ownDhKey.secretKey);
  return {
    version: Number(options.version || SIMPLEX_NATIVE_RATCHET_VERSION),
    maxSupportedVersion: Number(options.maxSupportedVersion || options.version || SIMPLEX_NATIVE_RATCHET_VERSION),
    associatedData: toBytes(init.associatedData || new Uint8Array(), 'associated data'),
    ownDhKey,
    remoteDhPublicKey,
    rootKey: derived.rootKey,
    sendingChainKey: derived.chainKey,
    sendingHeaderKey: toBytes(init.sendHeaderKey, 'sending header key'),
    nextSendingHeaderKey: derived.nextHeaderKey,
    nextReceivingHeaderKey: toBytes(init.receiveNextHeaderKey, 'next receiving header key'),
    sendCount: 0,
    previousSendCount: 0
  };
}

export function createNativeReceivingRatchet(options = {}) {
  var init = options.init || {};
  return {
    version: Number(options.version || SIMPLEX_NATIVE_RATCHET_VERSION),
    maxSupportedVersion: Number(options.maxSupportedVersion || options.version || SIMPLEX_NATIVE_RATCHET_VERSION),
    associatedData: toBytes(init.associatedData || new Uint8Array(), 'associated data'),
    ownDhKey: normalizeX448KeyPair(options.ownDhKey, 'receiving DH key'),
    rootKey: toBytes(init.ratchetKey, 'root key'),
    receivingHeaderKey: null,
    nextReceivingHeaderKey: toBytes(init.sendHeaderKey, 'next receiving header key'),
    nextSendingHeaderKey: toBytes(init.receiveNextHeaderKey, 'next sending header key'),
    receivingChainKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0
  };
}

export function encodeNativeMessageHeader(header = {}) {
  var publicKey = normalizeX448PublicKey(header.dh, 'header DH key');
  return concatBytes(
    encodeWord16(safeWord32(header.maxSupportedVersion || SIMPLEX_NATIVE_RATCHET_VERSION, 'max supported version')),
    encodeSmallBytes(encodePublicKeyDer('X448', publicKey)),
    encodeWord32(safeWord32(header.previousSendCount, 'previous send count')),
    encodeWord32(safeWord32(header.messageNumber, 'message number'))
  );
}

export function parseNativeMessageHeader(bytes) {
  var input = toBytes(bytes, 'native ratchet header');
  if (input.length < 2) fail('SIMPLEX_NATIVE_RATCHET_HEADER', 'native ratchet header is truncated');
  var maxSupportedVersion = decodeWord16(input, 0);
  var keyLength = input[2];
  var keyStart = 3;
  var keyEnd = keyStart + keyLength;
  if (keyEnd + 8 !== input.length) fail('SIMPLEX_NATIVE_RATCHET_HEADER', 'native ratchet header has invalid length');
  var dh = decodePublicKeyDer(input.slice(keyStart, keyEnd));
  if (dh.algorithm !== 'X448') fail('SIMPLEX_NATIVE_RATCHET_HEADER', 'native ratchet header DH key must be X448');
  return {
    maxSupportedVersion,
    dh: dh.rawPublicKey,
    previousSendCount: decodeWord32(input, keyEnd),
    messageNumber: decodeWord32(input, keyEnd + 4)
  };
}

function encodeMaybeLarge(version, bytes) {
  return version >= 3 ? encodeLargeBytes(bytes) : encodeSmallBytes(bytes);
}

function readMaybeLarge(bytes, offset) {
  var input = toBytes(bytes, 'native ratchet message');
  var first = input[offset];
  if (first < 32) {
    var length = decodeWord16(input, offset);
    return { value: input.slice(offset + 2, offset + 2 + length), next: offset + 2 + length };
  }
  return { value: input.slice(offset + 1, offset + 1 + first), next: offset + 1 + first };
}

function encodeEncryptedHeader(version, iv, tag, body) {
  return concatBytes(encodeWord16(version), iv, tag, encodeMaybeLarge(version, body));
}

function parseEncryptedHeader(bytes) {
  var input = toBytes(bytes, 'encrypted native ratchet header');
  if (input.length < 34) fail('SIMPLEX_NATIVE_RATCHET_HEADER', 'encrypted native ratchet header is truncated');
  var version = decodeWord16(input, 0);
  var iv = input.slice(2, 18);
  var tag = input.slice(18, 34);
  var body = readMaybeLarge(input, 34);
  if (body.next !== input.length) fail('SIMPLEX_NATIVE_RATCHET_HEADER', 'encrypted native ratchet header has trailing bytes');
  return { version, iv, tag, body: body.value };
}

export function encryptNativeRatchetMessage(stateInput, plaintext, options = {}) {
  var state = { ...stateInput };
  if (!state.sendingChainKey || !state.sendingHeaderKey) fail('SIMPLEX_NATIVE_RATCHET_STATE', 'native sending ratchet is not initialized');
  var chain = chainKdf(state.sendingChainKey);
  var headerPlain = encodeNativeMessageHeader({
    maxSupportedVersion: state.maxSupportedVersion || state.version,
    dh: state.ownDhKey.publicKey,
    previousSendCount: state.previousSendCount || 0,
    messageNumber: state.sendCount || 0
  });
  var encryptedHeader = encryptAead(
    state.sendingHeaderKey,
    options.headerIv || chain.headerIv,
    state.associatedData,
    headerPlain,
    SIMPLEX_NATIVE_RATCHET_HEADER_LENGTH
  );
  var encodedHeader = encodeEncryptedHeader(state.version, options.headerIv || chain.headerIv, encryptedHeader.tag, encryptedHeader.body);
  var encryptedBody = encryptAead(
    chain.messageKey,
    chain.messageIv,
    concatBytes(state.associatedData, encodedHeader),
    plaintext,
    options.paddedLength || Math.max(64, toBytes(plaintext, 'plaintext').length + 2)
  );
  state.sendingChainKey = chain.nextChainKey;
  state.sendCount = (state.sendCount || 0) + 1;
  return {
    state,
    packet: concatBytes(encodeMaybeLarge(state.version, encodedHeader), encryptedBody.tag, encryptedBody.body)
  };
}

export function decryptNativeRatchetMessage(stateInput, packet) {
  var state = { ...stateInput };
  var input = toBytes(packet, 'native ratchet packet');
  var headerPart = readMaybeLarge(input, 0);
  var encHeader = parseEncryptedHeader(headerPart.value);
  var tag = input.slice(headerPart.next, headerPart.next + 16);
  var body = input.slice(headerPart.next + 16);
  var headerKey = state.receivingHeaderKey || state.nextReceivingHeaderKey;
  var headerPlain = decryptAead(headerKey, encHeader.iv, state.associatedData, encHeader.body, encHeader.tag);
  var header = parseNativeMessageHeader(headerPlain);
  if (!state.receivingChainKey) {
    var derived = rootKdf(state.rootKey, header.dh, state.ownDhKey.secretKey);
    state.rootKey = derived.rootKey;
    state.receivingChainKey = derived.chainKey;
    state.receivingHeaderKey = state.nextReceivingHeaderKey;
    state.nextReceivingHeaderKey = derived.nextHeaderKey;
  }
  var chain = chainKdf(state.receivingChainKey);
  var plaintext = decryptAead(chain.messageKey, chain.messageIv, concatBytes(state.associatedData, headerPart.value), body, tag);
  state.receivingChainKey = chain.nextChainKey;
  state.receiveCount = (state.receiveCount || 0) + 1;
  return { state, header, plaintext };
}

export default {
  BrowserSimplexNativeRatchetError,
  SIMPLEX_NATIVE_RATCHET_HEADER_LENGTH,
  SIMPLEX_NATIVE_RATCHET_VERSION,
  createNativeReceivingRatchet,
  createNativeSendingRatchet,
  decryptNativeRatchetMessage,
  encodeNativeMessageHeader,
  encryptNativeRatchetMessage,
  parseNativeMessageHeader
};
