// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser-native XFTP web client profile.
//
// This module implements the browser-facing XFTP web transport shape used by
// upstream simplexmq's xftp-web work: binary 16384-byte protocol blocks over
// HTTPS/fetch, a web challenge in the first hello, server identity proof
// verification, a padded client handshake, authenticated XFTP commands, and
// padded binary responses. It is deliberately separate from the local
// encrypted-chunk JSON test transport so callers can choose the real web XFTP
// profile when talking to compatible servers.

import { ed448 } from '@noble/curves/ed448.js';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { sha512 } from '@noble/hashes/sha2.js';

import {
  asciiBytes,
  concatBytes,
  decodeBase64Url,
  decodeWord64,
  decodePublicKeyDer,
  ed25519Sign,
  ed25519Verify,
  encodeBase64Url,
  encodeLargeBytes,
  encodePrivateKeyDer,
  encodePublicKeyDer,
  encodeSmallBytes,
  encodeWord64,
  encodeWord16,
  encodeWord32,
  equalBytes,
  generateX25519KeyPair,
  generateEd25519KeyPair,
  hexToBytes,
  padBlock,
  randomBytes32,
  randomNonce24,
  sha256Hash,
  toBytes,
  unpadBlock,
  utf8Bytes,
  utf8Text,
  x25519SharedSecret
} from './browser-smp-core.mjs';

export const XFTP_WEB_BLOCK_SIZE = 16384;
export const XFTP_WEB_INITIAL_VERSION = 1;
export const XFTP_WEB_AUTH_COMMANDS_VERSION = 2;
export const XFTP_WEB_CURRENT_VERSION = 3;
export const XFTP_WEB_FILE_AUTH_TAG_SIZE = 16;
export const XFTP_WEB_FILE_SIZE_PREFIX_LENGTH = 8;
export const XFTP_WEB_SMALL_CHUNK_SIZE = 64 * 1024;
export const XFTP_WEB_MEDIUM_CHUNK_SIZE = 256 * 1024;
export const XFTP_WEB_LARGE_CHUNK_SIZE = 1024 * 1024;
export const XFTP_WEB_HUGE_CHUNK_SIZE = 4 * 1024 * 1024;
export const XFTP_WEB_MAX_DESCRIPTION_CHUNKS = 4096;
export const XFTP_WEB_MAX_DESCRIPTION_REPLICAS = 16;

export class BrowserXftpWebClientError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserXftpWebClientError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserXftpWebClientError(code, message);
}

function safeInteger(value, label, min, max) {
  var n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) fail('XFTP_WEB_RANGE', label + ' is outside the supported range');
  return n;
}

class ByteReader {
  constructor(bytes, label = 'XFTP bytes') {
    this.bytes = toBytes(bytes, label);
    this.pos = 0;
    this.label = label;
  }

  remaining() {
    return this.bytes.length - this.pos;
  }

  offset() {
    return this.pos;
  }

  take(length, label = 'field') {
    var n = safeInteger(length, label + ' length', 0, Number.MAX_SAFE_INTEGER);
    if (this.pos + n > this.bytes.length) fail('XFTP_WEB_TRUNCATED', label + ' is truncated');
    var out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  takeByte(label = 'byte') {
    if (this.pos >= this.bytes.length) fail('XFTP_WEB_TRUNCATED', label + ' is missing');
    return this.bytes[this.pos++];
  }

  takeSmall(label = 'small field') {
    return this.take(this.takeByte(label + ' length'), label);
  }

  takeLarge(label = 'large field') {
    var hi = this.takeByte(label + ' length hi');
    var lo = this.takeByte(label + ' length lo');
    return this.take((hi << 8) | lo, label);
  }

  takeTail() {
    return this.take(this.remaining(), 'tail');
  }

  assertDone(label = this.label) {
    if (this.remaining() !== 0) fail('XFTP_WEB_TRAILING', label + ' has trailing bytes');
  }
}

function encodeMaybeBytes(bytes) {
  if (bytes == null) return asciiBytes('0');
  return concatBytes(asciiBytes('1'), encodeSmallBytes(bytes));
}

function encodeNonEmptyBytes(values, label) {
  var list = Array.isArray(values) ? values : [];
  if (!list.length) fail('XFTP_WEB_LIST', label + ' must be non-empty');
  if (list.length > 255) fail('XFTP_WEB_LIST', label + ' has too many entries');
  return concatBytes(new Uint8Array([list.length]), ...list.map(encodeSmallBytes));
}

function decodeNonEmpty(reader, decode, label) {
  var length = reader.takeByte(label + ' length');
  if (length < 1) fail('XFTP_WEB_LIST', label + ' must be non-empty');
  var out = [];
  for (var i = 0; i < length; i += 1) out.push(decode(reader));
  return out;
}

function decodeWord16FromReader(reader, label) {
  var hi = reader.takeByte(label + ' hi');
  var lo = reader.takeByte(label + ' lo');
  return (hi << 8) | lo;
}

function readTag(reader) {
  var start = reader.offset();
  while (reader.remaining() > 0) {
    var byte = reader.bytes[reader.offset()];
    if (byte === 0x20 || byte === 0x0a) break;
    reader.takeByte('tag byte');
  }
  return String.fromCharCode(...reader.bytes.slice(start, reader.offset()));
}

function readSpace(reader) {
  if (reader.takeByte('space') !== 0x20) fail('XFTP_WEB_PARSE', 'expected a space');
}

function isCapsError(bytes) {
  if (!bytes.length || bytes.length >= 20) return false;
  for (var byte of bytes) {
    if (!(byte === 0x5f || (byte >= 0x41 && byte <= 0x5a))) return false;
  }
  return true;
}

export function encodeXftpWebVersionRange(range = {}) {
  return concatBytes(
    encodeWord16(safeInteger(range.minVersion, 'minimum XFTP version', 1, 0xffff)),
    encodeWord16(safeInteger(range.maxVersion, 'maximum XFTP version', 1, 0xffff))
  );
}

export function chooseXftpWebVersion(serverRange, clientRange = {}) {
  var min = Math.max(
    safeInteger(serverRange.minVersion, 'server minimum XFTP version', 1, 0xffff),
    safeInteger(clientRange.minVersion || XFTP_WEB_INITIAL_VERSION, 'client minimum XFTP version', 1, 0xffff)
  );
  var max = Math.min(
    safeInteger(serverRange.maxVersion, 'server maximum XFTP version', 1, 0xffff),
    safeInteger(clientRange.maxVersion || XFTP_WEB_CURRENT_VERSION, 'client maximum XFTP version', 1, 0xffff)
  );
  if (min > max) fail('XFTP_WEB_VERSION', 'XFTP web version ranges are incompatible');
  return max;
}

export function encodeXftpWebClientHello(options = {}) {
  var challenge = options.webChallenge == null ? null : toBytes(options.webChallenge, 'XFTP web challenge');
  if (challenge && challenge.length !== 32) fail('XFTP_WEB_CHALLENGE', 'XFTP web challenge must be 32 bytes');
  var body = encodeMaybeBytes(challenge);
  return challenge ? padBlock(body, XFTP_WEB_BLOCK_SIZE) : body;
}

export function encodeXftpWebClientHandshake(options = {}) {
  var version = safeInteger(options.version, 'XFTP version', 1, 0xffff);
  var keyHash = toBytes(options.keyHash || new Uint8Array(), 'XFTP server identity hash');
  if (keyHash.length !== 32) fail('XFTP_WEB_KEY_HASH', 'XFTP server identity hash must be 32 bytes');
  return padBlock(concatBytes(encodeWord16(version), encodeSmallBytes(keyHash)), XFTP_WEB_BLOCK_SIZE);
}

export function decodeXftpWebServerHandshake(block) {
  var raw = unpadBlock(block, XFTP_WEB_BLOCK_SIZE);
  if (isCapsError(raw)) fail('XFTP_WEB_HANDSHAKE', 'XFTP web server handshake failed: ' + String.fromCharCode(...raw));
  var reader = new ByteReader(raw, 'XFTP web server handshake');
  var minVersion = decodeWord16FromReader(reader, 'server minimum version');
  var maxVersion = decodeWord16FromReader(reader, 'server maximum version');
  if (minVersion > maxVersion) fail('XFTP_WEB_VERSION', 'XFTP web server version range is invalid');
  var sessionId = reader.takeSmall('XFTP web session id');
  var certChainDer = decodeNonEmpty(reader, (r) => r.takeLarge('certificate'), 'certificate chain');
  var signedKeyDer = reader.takeLarge('signed server key');
  var webIdentityProof = null;
  if (reader.remaining() > 0) {
    var proof = reader.takeSmall('web identity proof');
    webIdentityProof = proof.length ? proof : null;
  }
  return {
    minVersion,
    maxVersion,
    xftpVersionRange: { minVersion, maxVersion },
    sessionId,
    certChainDer,
    signedKeyDer,
    webIdentityProof,
    tail: reader.takeTail()
  };
}

export function encodeXftpWebFileInfo(info = {}) {
  var size = safeInteger(info.size, 'XFTP file size', 0, 0xffffffff);
  var digest = toBytes(info.digest || new Uint8Array(), 'XFTP file digest');
  if (digest.length !== 32) fail('XFTP_WEB_DIGEST', 'XFTP file digest must be 32 bytes');
  return concatBytes(
    encodeSmallBytes(info.sndKey || info.senderPublicKeyDer || new Uint8Array()),
    encodeWord32(size),
    encodeSmallBytes(digest)
  );
}

export function encodeXftpWebFNEW(file, recipientKeys, auth = null) {
  return concatBytes(
    asciiBytes('FNEW '),
    encodeXftpWebFileInfo(file),
    encodeNonEmptyBytes(recipientKeys, 'recipient keys'),
    auth == null ? asciiBytes('0') : concatBytes(asciiBytes('1'), encodeSmallBytes(auth))
  );
}

export function encodeXftpWebFADD(recipientKeys) {
  return concatBytes(asciiBytes('FADD '), encodeNonEmptyBytes(recipientKeys, 'recipient keys'));
}

export function encodeXftpWebFPUT() {
  return asciiBytes('FPUT');
}

export function encodeXftpWebFDEL() {
  return asciiBytes('FDEL');
}

export function encodeXftpWebFGET(publicDhKey) {
  var key = toBytes(publicDhKey || new Uint8Array(), 'XFTP download public DH key');
  var der = key.length === 32 ? encodePublicKeyDer('X25519', key) : key;
  return concatBytes(asciiBytes('FGET '), encodeSmallBytes(der));
}

export function encodeXftpWebPING() {
  return asciiBytes('PING');
}

export function decodeXftpWebResponse(bytes) {
  var reader = new ByteReader(bytes, 'XFTP web response');
  var tag = readTag(reader);
  switch (tag) {
    case 'SIDS': {
      readSpace(reader);
      var senderId = reader.takeSmall('sender id');
      var recipientIds = decodeNonEmpty(reader, (r) => r.takeSmall('recipient id'), 'recipient ids');
      reader.assertDone('SIDS response');
      return { type: 'SIDS', senderId, recipientIds };
    }
    case 'RIDS': {
      readSpace(reader);
      var ids = decodeNonEmpty(reader, (r) => r.takeSmall('recipient id'), 'recipient ids');
      reader.assertDone('RIDS response');
      return { type: 'RIDS', recipientIds: ids };
    }
    case 'FILE': {
      readSpace(reader);
      var publicKey = decodePublicKeyDer(reader.takeSmall('recipient DH key'));
      if (publicKey.algorithm !== 'X25519') fail('XFTP_WEB_KEY', 'FILE response DH key must be X25519');
      var nonce = reader.take(24, 'FILE nonce');
      reader.assertDone('FILE response');
      return { type: 'FILE', rcvDhKey: publicKey.rawPublicKey, nonce };
    }
    case 'OK':
      reader.assertDone('OK response');
      return { type: 'OK' };
    case 'ERR':
      readSpace(reader);
      return { type: 'ERR', error: reader.takeTail() };
    case 'PONG':
      reader.assertDone('PONG response');
      return { type: 'PONG' };
    default:
      fail('XFTP_WEB_RESPONSE', 'unknown XFTP web response: ' + tag);
  }
}

function encodeXftpTransmissionBody(sessionId, corrId, entityId, commandBytes) {
  return concatBytes(
    encodeSmallBytes(sessionId),
    encodeSmallBytes(corrId || new Uint8Array()),
    encodeSmallBytes(entityId || new Uint8Array()),
    commandBytes
  );
}

export function encodeXftpWebTransmission(options = {}) {
  var body = encodeXftpTransmissionBody(
    toBytes(options.sessionId || new Uint8Array(), 'XFTP session id'),
    toBytes(options.corrId || new Uint8Array(), 'XFTP correlation id'),
    toBytes(options.entityId || new Uint8Array(), 'XFTP entity id'),
    toBytes(options.commandBytes || options.command || new Uint8Array(), 'XFTP command')
  );
  var tx = concatBytes(encodeSmallBytes(new Uint8Array()), body);
  return padBlock(concatBytes(new Uint8Array([1]), encodeLargeBytes(tx)), XFTP_WEB_BLOCK_SIZE);
}

export function encodeXftpWebAuthTransmission(options = {}) {
  var sessionId = toBytes(options.sessionId || new Uint8Array(), 'XFTP session id');
  var inner = encodeXftpTransmissionBody(
    sessionId,
    toBytes(options.corrId || new Uint8Array(), 'XFTP correlation id'),
    toBytes(options.entityId || new Uint8Array(), 'XFTP entity id'),
    toBytes(options.commandBytes || options.command || new Uint8Array(), 'XFTP command')
  );
  var signature = ed25519Sign(options.privateKey || options.senderPrivateKey, inner);
  var tx = concatBytes(encodeSmallBytes(signature), inner);
  return padBlock(concatBytes(new Uint8Array([1]), encodeLargeBytes(tx)), XFTP_WEB_BLOCK_SIZE);
}

export function decodeXftpWebTransmission(sessionId, block) {
  var expectedSessionId = toBytes(sessionId || new Uint8Array(), 'expected XFTP session id');
  var raw = unpadBlock(block, XFTP_WEB_BLOCK_SIZE);
  if (isCapsError(raw)) fail('XFTP_WEB_TRANSMISSION', 'XFTP web transmission failed: ' + String.fromCharCode(...raw));
  var batch = new ByteReader(raw, 'XFTP web transmission batch');
  var count = batch.takeByte('batch count');
  if (count !== 1) fail('XFTP_WEB_BATCH', 'XFTP web profile expects one transmission per block');
  var tx = new ByteReader(batch.takeLarge('batched transmission'), 'XFTP web transmission');
  var signature = tx.takeSmall('authenticator');
  var gotSessionId = tx.takeSmall('session id');
  if (!equalBytes(gotSessionId, expectedSessionId)) fail('XFTP_WEB_SESSION', 'XFTP web session id mismatch');
  var corrId = tx.takeSmall('correlation id');
  var entityId = tx.takeSmall('entity id');
  var commandBytes = tx.takeTail();
  batch.assertDone('XFTP web transmission batch');
  return { signature, sessionId: gotSessionId, corrId, entityId, commandBytes };
}

export function decodeXftpWebBrokerTransmission(sessionId, block) {
  var tx = decodeXftpWebTransmission(sessionId, block);
  return { ...tx, response: decodeXftpWebResponse(tx.commandBytes) };
}

function assertByteLength(bytes, length, label) {
  if (toBytes(bytes, label).length !== length) fail('XFTP_WEB_LENGTH', label + ' must be ' + length + ' bytes');
}

function sumNumbers(values) {
  return values.reduce((sum, value) => sum + value, 0);
}

function threeQuarter(value) {
  return Math.floor(value * 3 / 4);
}

// Upstream XFTP grows chunks in bands.  Small files are padded to 64 KiB
// chunks; larger files step up to 256 KiB, 1 MiB, and 4 MiB chunks so the
// receiver can verify deterministic offsets without trusting server metadata.
function chooseChunkBands(payloadSize) {
  if (payloadSize > threeQuarter(XFTP_WEB_HUGE_CHUNK_SIZE)) {
    return { small: XFTP_WEB_LARGE_CHUNK_SIZE, big: XFTP_WEB_HUGE_CHUNK_SIZE };
  }
  if (payloadSize > threeQuarter(XFTP_WEB_LARGE_CHUNK_SIZE)) {
    return { small: XFTP_WEB_MEDIUM_CHUNK_SIZE, big: XFTP_WEB_LARGE_CHUNK_SIZE };
  }
  return { small: XFTP_WEB_SMALL_CHUNK_SIZE, big: XFTP_WEB_MEDIUM_CHUNK_SIZE };
}

function prepareSizeList(size, bands) {
  if (size === 0) return [];
  if (size >= bands.big) {
    var bigCount = Math.floor(size / bands.big);
    return [
      ...new Array(bigCount).fill(bands.big),
      ...prepareSizeList(size % bands.big, bands)
    ];
  }
  if (size > threeQuarter(bands.big)) return [bands.big];
  var smallCount = Math.floor(size / bands.small);
  return new Array(size % bands.small === 0 ? smallCount : smallCount + 1).fill(bands.small);
}

export function prepareXftpWebChunkSizes(payloadSize) {
  var size = safeInteger(payloadSize, 'XFTP encrypted payload size', 0, Number.MAX_SAFE_INTEGER);
  return prepareSizeList(size, chooseChunkBands(size));
}

export function prepareXftpWebChunkSpecs(payloadSize) {
  var offset = 0;
  return prepareXftpWebChunkSizes(payloadSize).map((chunkSize, index) => {
    var spec = { chunkNo: index + 1, offset, chunkSize };
    offset += chunkSize;
    return spec;
  });
}

function encodeXftpWebString(value, label) {
  var bytes = utf8Bytes(value);
  if (bytes.length > 255) fail('XFTP_WEB_LENGTH', label + ' must encode to 255 bytes or less');
  return encodeSmallBytes(bytes);
}

function decodeXftpWebString(reader, label) {
  try {
    return utf8Text(reader.takeSmall(label));
  } catch (_error) {
    fail('XFTP_WEB_UTF8', label + ' is not valid UTF-8');
  }
}

function encodeXftpWebMaybeString(value, label) {
  if (value == null) return asciiBytes('0');
  return concatBytes(asciiBytes('1'), encodeXftpWebString(value, label));
}

function decodeXftpWebMaybeString(reader, label) {
  var tag = reader.takeByte(label + ' maybe tag');
  if (tag === 0x30) return null;
  if (tag === 0x31) return decodeXftpWebString(reader, label);
  fail('XFTP_WEB_PARSE', label + ' maybe tag is invalid');
}

// The file header is part of the encrypted file envelope.  It stores metadata
// that the XFTP server must not see, so callers should keep names small and
// filename-like rather than passing paths or control characters.
function safeXftpWebFileName(value) {
  var name = String(value == null || value === '' ? 'file' : value);
  if (/[\x00-\x1f\x7f]/.test(name)) fail('XFTP_WEB_FILENAME', 'XFTP file name contains a control character');
  if (/[\\/]/.test(name)) fail('XFTP_WEB_FILENAME', 'XFTP file name must not contain a path separator');
  if (utf8Bytes(name).length > 255) fail('XFTP_WEB_FILENAME', 'XFTP file name must encode to 255 bytes or less');
  return name;
}

export function encodeXftpWebFileHeader(header = {}) {
  return concatBytes(
    encodeXftpWebString(safeXftpWebFileName(header.fileName), 'XFTP file name'),
    encodeXftpWebMaybeString(header.fileExtra == null ? null : String(header.fileExtra), 'XFTP file extra')
  );
}

export function decodeXftpWebFileHeader(bytes) {
  var reader = new ByteReader(bytes, 'XFTP file header');
  var fileName = decodeXftpWebString(reader, 'XFTP file name');
  var fileExtra = decodeXftpWebMaybeString(reader, 'XFTP file extra');
  return {
    fileName,
    fileExtra,
    contentOffset: reader.offset()
  };
}

function normalizeXftpWebFileKey(key) {
  var next = key == null ? randomBytes32() : toBytes(key, 'XFTP file encryption key');
  assertByteLength(next, 32, 'XFTP file encryption key');
  return next;
}

function normalizeXftpWebFileNonce(nonce) {
  var next = nonce == null ? randomNonce24() : toBytes(nonce, 'XFTP file encryption nonce');
  assertByteLength(next, 24, 'XFTP file encryption nonce');
  return next;
}

function xftpWebSha512Hash(bytes) {
  return sha512(toBytes(bytes, 'XFTP SHA-512 input'));
}

function encodeBase64UrlPadded(bytes) {
  var text = encodeBase64Url(bytes);
  while (text.length % 4) text += '=';
  return text;
}

function encodeMaybeBase64UrlString(value) {
  if (value == null) return '-';
  return encodeBase64UrlPadded(utf8Bytes(String(value)));
}

function decodeMaybeBase64UrlString(value, label) {
  var text = String(value == null ? '' : value).trim();
  if (text === '-') return null;
  try {
    return utf8Text(decodeBase64Url(text, label));
  } catch (_error) {
    fail('XFTP_WEB_DESCRIPTION', label + ' is invalid');
  }
}

function formatXftpWebDescriptionSize(value) {
  var n = safeInteger(value, 'XFTP description size', 0, Number.MAX_SAFE_INTEGER);
  if (n >= XFTP_WEB_HUGE_CHUNK_SIZE && n % XFTP_WEB_HUGE_CHUNK_SIZE === 0) return String(n / XFTP_WEB_HUGE_CHUNK_SIZE * 4) + 'mb';
  if (n >= 1024 * 1024 && n % (1024 * 1024) === 0) return String(n / (1024 * 1024)) + 'mb';
  if (n >= 1024 && n % 1024 === 0) return String(n / 1024) + 'kb';
  return String(n);
}

function parseXftpWebDescriptionSize(value, label) {
  var match = /^([0-9]+)(kb|mb|gb)?$/i.exec(String(value == null ? '' : value).trim());
  if (!match) fail('XFTP_WEB_DESCRIPTION', label + ' is not a valid size');
  var multiplier = match[2] ? { kb: 1024, mb: 1024 * 1024, gb: 1024 * 1024 * 1024 }[match[2].toLowerCase()] : 1;
  return safeInteger(Number(match[1]) * multiplier, label, 0, Number.MAX_SAFE_INTEGER);
}

function parseXftpWebDescriptionBytes(value, label, length = null) {
  var bytes = decodeBase64Url(String(value == null ? '' : value).trim(), label);
  if (length != null && bytes.length !== length) fail('XFTP_WEB_DESCRIPTION', label + ' has the wrong length');
  return bytes;
}

export function encryptXftpWebFileEnvelope(source, options = {}) {
  var content = toBytes(source || new Uint8Array(), 'XFTP file content');
  var header = {
    fileName: safeXftpWebFileName(options.fileName),
    fileExtra: options.fileExtra == null ? null : String(options.fileExtra)
  };
  var headerBytes = encodeXftpWebFileHeader(header);
  var clearFileSize = headerBytes.length + content.length;
  safeInteger(clearFileSize, 'XFTP clear file size', 0, Number.MAX_SAFE_INTEGER);
  var payloadSize = clearFileSize + XFTP_WEB_FILE_SIZE_PREFIX_LENGTH + XFTP_WEB_FILE_AUTH_TAG_SIZE;
  var chunkSizes = prepareXftpWebChunkSizes(payloadSize);
  var encryptedSize = sumNumbers(chunkSizes);
  var paddingLength = encryptedSize - XFTP_WEB_FILE_AUTH_TAG_SIZE - XFTP_WEB_FILE_SIZE_PREFIX_LENGTH - clearFileSize;
  if (paddingLength < 0) fail('XFTP_WEB_CHUNK', 'XFTP file chunk plan is too small for the payload');
  var key = normalizeXftpWebFileKey(options.key);
  var nonce = normalizeXftpWebFileNonce(options.nonce);
  // The clear envelope starts with the unpadded file size, then the encrypted
  // header/content body, then `#` padding.  XSalsa20-Poly1305 appends the
  // 16-byte tag, making the ciphertext length exactly match the chunk plan.
  var plaintext = concatBytes(
    encodeWord64(BigInt(clearFileSize)),
    headerBytes,
    content,
    new Uint8Array(paddingLength).fill(0x23)
  );
  var encrypted = xsalsa20poly1305(key, nonce).encrypt(plaintext);
  if (encrypted.length !== encryptedSize) fail('XFTP_WEB_CHUNK', 'XFTP file envelope size does not match chunk plan');
  return {
    header,
    key,
    nonce,
    encrypted,
    digest: xftpWebSha512Hash(encrypted),
    clearFileSize,
    encryptedSize,
    chunkSizes,
    chunkSpecs: prepareXftpWebChunkSpecs(payloadSize)
  };
}

export function decryptXftpWebFileEnvelope(encryptedFile, options = {}) {
  var encrypted = Array.isArray(encryptedFile)
    ? concatBytes(...encryptedFile)
    : toBytes(encryptedFile || new Uint8Array(), 'XFTP encrypted file');
  if (options.size != null && encrypted.length !== safeInteger(options.size, 'XFTP encrypted file size', 0, Number.MAX_SAFE_INTEGER)) {
    fail('XFTP_WEB_SIZE', 'XFTP encrypted file size mismatch');
  }
  if (options.digest != null && !equalBytes(xftpWebSha512Hash(encrypted), options.digest)) {
    fail('XFTP_WEB_DIGEST', 'XFTP encrypted file digest mismatch');
  }
  if (options.key == null) fail('XFTP_WEB_KEY', 'XFTP file decryption key is required');
  if (options.nonce == null) fail('XFTP_WEB_NONCE', 'XFTP file decryption nonce is required');
  var key = normalizeXftpWebFileKey(options.key);
  var nonce = normalizeXftpWebFileNonce(options.nonce);
  var plaintext;
  try {
    plaintext = xsalsa20poly1305(key, nonce).decrypt(encrypted);
  } catch (_error) {
    fail('XFTP_WEB_DECRYPT', 'XFTP file envelope decryption failed');
  }
  var clearFileSize = decodeWord64(plaintext, 0);
  if (clearFileSize > BigInt(Number.MAX_SAFE_INTEGER)) fail('XFTP_WEB_SIZE', 'XFTP clear file size is too large for this JavaScript runtime');
  var clearLength = Number(clearFileSize);
  var clearEnd = XFTP_WEB_FILE_SIZE_PREFIX_LENGTH + clearLength;
  if (clearEnd > plaintext.length) fail('XFTP_WEB_TRUNCATED', 'XFTP file envelope clear body is truncated');
  // After authentication succeeds, padding is still checked explicitly so a
  // malformed local description cannot reinterpret garbage as file content.
  var padding = plaintext.slice(clearEnd);
  for (var i = 0; i < padding.length; i += 1) {
    if (padding[i] !== 0x23) fail('XFTP_WEB_PADDING', 'XFTP file envelope padding is invalid');
  }
  var body = plaintext.slice(XFTP_WEB_FILE_SIZE_PREFIX_LENGTH, clearEnd);
  var header = decodeXftpWebFileHeader(body);
  return {
    header: {
      fileName: header.fileName,
      fileExtra: header.fileExtra
    },
    content: body.slice(header.contentOffset),
    clearFileSize: clearLength,
    encryptedSize: encrypted.length,
    digest: xftpWebSha512Hash(encrypted)
  };
}

export function encryptXftpWebTransportChunk(dhSecret, nonce, plaintext) {
  var key = toBytes(dhSecret, 'XFTP web transport DH secret');
  if (key.length !== 32) fail('XFTP_WEB_KEY', 'XFTP web transport DH secret must be 32 bytes');
  var nonceBytes = toBytes(nonce, 'XFTP web transport nonce');
  if (nonceBytes.length !== 24) fail('XFTP_WEB_NONCE', 'XFTP web transport nonce must be 24 bytes');
  return xsalsa20poly1305(key, nonceBytes).encrypt(toBytes(plaintext || new Uint8Array(), 'XFTP web transport plaintext'));
}

export function decryptXftpWebTransportChunk(dhSecret, nonce, encryptedBody, expectedDigest = null) {
  var key = toBytes(dhSecret, 'XFTP web transport DH secret');
  if (key.length !== 32) fail('XFTP_WEB_KEY', 'XFTP web transport DH secret must be 32 bytes');
  var nonceBytes = toBytes(nonce, 'XFTP web transport nonce');
  if (nonceBytes.length !== 24) fail('XFTP_WEB_NONCE', 'XFTP web transport nonce must be 24 bytes');
  var body = toBytes(encryptedBody || new Uint8Array(), 'XFTP web transport encrypted body');
  try {
    var plaintext = xsalsa20poly1305(key, nonceBytes).decrypt(body);
    if (expectedDigest != null && !equalBytes(sha256Hash(plaintext), expectedDigest)) {
      fail('XFTP_WEB_DIGEST', 'XFTP web downloaded chunk digest mismatch');
    }
    return plaintext;
  } catch (error) {
    if (error instanceof BrowserXftpWebClientError) throw error;
    fail('XFTP_WEB_DECRYPT', 'XFTP web transport chunk decryption failed');
  }
}

export function parseXftpWebServerAddress(value) {
  var text = String(value == null ? '' : value).trim();
  var match = /^xftp:\/\/([A-Za-z0-9_-]+={0,2})@([^:#,;\/\s]+)(?::([0-9]+))?$/.exec(text);
  if (!match) fail('XFTP_WEB_ADDRESS', 'XFTP server address is invalid');
  var keyHash = decodeBase64Url(match[1], 'XFTP server identity hash');
  if (keyHash.length !== 32) fail('XFTP_WEB_KEY_HASH', 'XFTP server identity hash must be 32 bytes');
  var port = match[3] || '443';
  safeInteger(port, 'XFTP server port', 1, 65535);
  return {
    keyHash,
    host: match[2],
    port
  };
}

export function formatXftpWebServerAddress(server = {}) {
  var keyHash = toBytes(server.keyHash || new Uint8Array(), 'XFTP server identity hash');
  if (keyHash.length !== 32) fail('XFTP_WEB_KEY_HASH', 'XFTP server identity hash must be 32 bytes');
  var host = String(server.host || '').trim();
  if (!host || /[:#,;\/\s]/.test(host)) fail('XFTP_WEB_ADDRESS', 'XFTP server host is invalid');
  var port = String(server.port || '443').trim();
  safeInteger(port, 'XFTP server port', 1, 65535);
  return 'xftp://' + encodeBase64Url(keyHash) + '@' + host + ':' + port;
}

function isLoopbackHost(hostname) {
  var host = String(hostname || '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

export function normalizeXftpWebUrl(value, options = {}) {
  var raw = String(value || '').trim();
  if (!raw) fail('XFTP_WEB_URL', 'XFTP web URL is required');
  var parsed;
  try {
    parsed = new URL(raw, globalThis.location && globalThis.location.href || 'https://example.invalid/');
  } catch (_error) {
    fail('XFTP_WEB_URL', 'XFTP web URL is invalid');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') fail('XFTP_WEB_URL', 'XFTP web URL must use https://');
  if (parsed.protocol === 'http:' && (!isLoopbackHost(parsed.hostname) || options.allowInsecureLocal !== true)) {
    fail('XFTP_WEB_SECURITY', 'XFTP web URL requires https:// outside explicit loopback tests');
  }
  parsed.username = '';
  parsed.password = '';
  parsed.hash = '';
  return parsed.href;
}

function serverUrl(server) {
  if (server.url) return server.url;
  var host = String(server.host || '').trim();
  var port = String(server.port || '443').trim();
  if (!host) fail('XFTP_WEB_ADDRESS', 'XFTP server host is required');
  return 'https://' + host + (port === '443' ? '' : ':' + port) + '/';
}

async function postBytes(fetchImpl, url, body, headers, timeoutMs) {
  var controller = typeof AbortController === 'function' ? new AbortController() : null;
  var timer = controller ? setTimeout(() => controller.abort(), Math.max(1, Math.floor(timeoutMs || 30000))) : null;
  try {
    var response = await fetchImpl(url, {
      method: 'POST',
      headers,
      body,
      signal: controller ? controller.signal : undefined
    });
    if (!response || !response.ok) {
      var detail = '';
      try {
        detail = response && typeof response.text === 'function' ? String(await response.text()).slice(0, 240) : '';
      } catch (_error) {}
      fail('XFTP_WEB_HTTP', 'XFTP web request failed with status ' + (response ? response.status : 'unknown') + (detail ? ': ' + detail : ''));
    }
    return new Uint8Array(await response.arrayBuffer());
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function derLengthBytes(length) {
  if (length < 0x80) return new Uint8Array([length]);
  var bytes = [];
  var n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function derSequence(...parts) {
  var body = concatBytes(...parts);
  return concatBytes(new Uint8Array([0x30]), derLengthBytes(body.length), body);
}

function derBitString(bytes) {
  var body = concatBytes(new Uint8Array([0]), bytes);
  return concatBytes(new Uint8Array([0x03]), derLengthBytes(body.length), body);
}

function readDerLength(reader) {
  var first = reader.takeByte('DER length');
  if (first < 0x80) return first;
  var count = first & 0x7f;
  if (count < 1 || count > 4) fail('XFTP_WEB_DER', 'DER length encoding is unsupported');
  var length = 0;
  for (var i = 0; i < count; i += 1) length = (length << 8) | reader.takeByte('DER length byte');
  return length;
}

function skipDerElement(reader) {
  reader.takeByte('DER tag');
  reader.take(readDerLength(reader), 'DER value');
}

function readDerElement(reader) {
  var start = reader.offset();
  reader.takeByte('DER tag');
  reader.take(readDerLength(reader), 'DER value');
  return reader.bytes.slice(start, reader.offset());
}

export function extractXftpWebCertPublicKeyInfo(certDer) {
  var cert = new ByteReader(certDer, 'X.509 certificate');
  if (cert.takeByte('certificate sequence tag') !== 0x30) fail('XFTP_WEB_CERT', 'certificate must be a DER sequence');
  readDerLength(cert);
  if (cert.takeByte('tbs certificate sequence tag') !== 0x30) fail('XFTP_WEB_CERT', 'certificate TBS body must be a DER sequence');
  readDerLength(cert);
  if (cert.remaining() > 0 && cert.bytes[cert.offset()] === 0xa0) skipDerElement(cert);
  skipDerElement(cert);
  skipDerElement(cert);
  skipDerElement(cert);
  skipDerElement(cert);
  skipDerElement(cert);
  return readDerElement(cert);
}

function chainIdCaCerts(certChainDer) {
  var chain = Array.isArray(certChainDer) ? certChainDer : [];
  if (chain.length === 2) return { type: 'valid', leafCert: chain[0], idCert: chain[1], caCert: chain[1] };
  if (chain.length === 3) return { type: 'valid', leafCert: chain[0], idCert: chain[1], caCert: chain[2] };
  if (chain.length === 4) return { type: 'valid', leafCert: chain[0], idCert: chain[1], caCert: chain[3] };
  return { type: 'invalid' };
}

function decodeEd448PublicKeyDer(spki) {
  var der = toBytes(spki, 'Ed448 public key DER');
  var prefix = new Uint8Array([0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00]);
  if (der.length !== prefix.length + 57) fail('XFTP_WEB_KEY', 'Ed448 public key DER has invalid length');
  for (var i = 0; i < prefix.length; i += 1) {
    if (der[i] !== prefix[i]) fail('XFTP_WEB_KEY', 'Ed448 public key DER has invalid prefix');
  }
  return der.slice(prefix.length);
}

function certKey(certDer) {
  var spki = extractXftpWebCertPublicKeyInfo(certDer);
  if (spki.length === 44 && spki[8] === 0x70) {
    var ed = decodePublicKeyDer(spki);
    return { algorithm: 'Ed25519', publicKey: ed.rawPublicKey };
  }
  if (spki.length === 69 && spki[8] === 0x71) {
    return { algorithm: 'Ed448', publicKey: decodeEd448PublicKeyDer(spki) };
  }
  fail('XFTP_WEB_KEY', 'certificate public key algorithm is unsupported');
}

export function encodeXftpWebSignedKeyForTests(objectDer, leafPrivateKey) {
  var object = toBytes(objectDer, 'signed object');
  var algorithm = derSequence(new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]));
  return derSequence(object, algorithm, derBitString(ed25519Sign(leafPrivateKey, object)));
}

export function extractXftpWebSignedKey(signedKeyDer) {
  var reader = new ByteReader(signedKeyDer, 'signed key DER');
  if (reader.takeByte('signed key sequence tag') !== 0x30) fail('XFTP_WEB_SIGNED_KEY', 'signed key must be a DER sequence');
  readDerLength(reader);
  var objectDer = readDerElement(reader);
  var algorithm = readDerElement(reader);
  if (reader.takeByte('signature bit string tag') !== 0x03) fail('XFTP_WEB_SIGNED_KEY', 'signed key signature must be a DER bit string');
  var sigLength = readDerLength(reader);
  if (reader.takeByte('unused bits') !== 0) fail('XFTP_WEB_SIGNED_KEY', 'signed key bit string must have zero unused bits');
  var signature = reader.take(sigLength - 1, 'signed key signature');
  reader.assertDone('signed key DER');
  return { objectDer, algorithm, signature };
}

function verifyCertSignature(key, signature, message) {
  if (key.algorithm === 'Ed25519') return ed25519Verify(key.publicKey, message, signature);
  if (key.algorithm === 'Ed448') {
    try {
      return ed448.verify(signature, message, key.publicKey);
    } catch (_error) {
      return false;
    }
  }
  return false;
}

export function verifyXftpWebIdentityProof(options = {}) {
  var handshake = options.handshake || options;
  var chain = chainIdCaCerts(handshake.certChainDer);
  if (chain.type !== 'valid') return false;
  var expectedKeyHash = toBytes(options.keyHash || new Uint8Array(), 'XFTP server identity hash');
  if (!equalBytes(sha256Hash(chain.idCert), expectedKeyHash)) return false;
  var leaf = certKey(chain.leafCert);
  var challenge = toBytes(options.challenge || new Uint8Array(), 'XFTP web challenge');
  var sessionId = toBytes(handshake.sessionId || options.sessionId || new Uint8Array(), 'XFTP session id');
  var proof = toBytes(handshake.webIdentityProof || options.webIdentityProof || new Uint8Array(), 'XFTP web identity proof');
  if (!proof.length || !verifyCertSignature(leaf, proof, concatBytes(challenge, sessionId))) return false;
  var signedKey = extractXftpWebSignedKey(handshake.signedKeyDer || new Uint8Array());
  return verifyCertSignature(leaf, signedKey.signature, signedKey.objectDer);
}

export async function connectBrowserXftpWebClient(options = {}) {
  var fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') fail('XFTP_WEB_FETCH', 'fetch is not available');
  var server = options.server || (options.address ? parseXftpWebServerAddress(options.address) : {});
  var keyHash = toBytes(options.keyHash || server.keyHash || new Uint8Array(), 'XFTP server identity hash');
  if (keyHash.length !== 32) fail('XFTP_WEB_KEY_HASH', 'XFTP server identity hash must be 32 bytes');
  var url = normalizeXftpWebUrl(options.url || serverUrl(server), options);
  var challenge = options.challenge ? toBytes(options.challenge, 'XFTP web challenge') : randomBytes32();
  var timeoutMs = Math.max(1, Math.floor(Number(options.timeoutMs || 30000) || 30000));
  var helloResponse = await postBytes(fetchImpl, url, encodeXftpWebClientHello({ webChallenge: challenge }), {
    'xftp-web-hello': '1',
    'content-type': 'application/octet-stream',
    accept: 'application/octet-stream'
  }, timeoutMs);
  var handshake = decodeXftpWebServerHandshake(helloResponse);
  var allowUnverified = options.allowUnverifiedIdentityForTests === true && isLoopbackHost(new URL(url).hostname);
  if (!allowUnverified && !verifyXftpWebIdentityProof({ handshake, challenge, keyHash })) {
    fail('XFTP_WEB_IDENTITY', 'XFTP web server identity proof is invalid');
  }
  var version = chooseXftpWebVersion(handshake, options.clientRange || {});
  var ack = await postBytes(fetchImpl, url, encodeXftpWebClientHandshake({ version, keyHash }), {
    'xftp-handshake': '1',
    'content-type': 'application/octet-stream',
    accept: 'application/octet-stream'
  }, timeoutMs);
  if (ack.length !== 0) fail('XFTP_WEB_HANDSHAKE', 'XFTP web client handshake returned a non-empty acknowledgement');
  return {
    profile: 'simplex-xftp-web-browser-v1',
    url,
    version,
    sessionId: handshake.sessionId,
    keyHash,
    handshake,
    security: {
      plaintextBridge: false,
      browserNativeProtocol: true,
      binaryXftpBlocksOnly: true,
      serverIdentityProof: !allowUnverified,
      unverifiedLoopbackTestMode: allowUnverified
    },
    async postBlock(block, headers) {
      return postBytes(fetchImpl, url, block, {
        'content-type': 'application/octet-stream',
        accept: 'application/octet-stream',
        ...(headers || {})
      }, timeoutMs);
    },
    close() {}
  };
}

export async function sendXftpWebCommand(client, options = {}) {
  var commandBytes = toBytes(options.commandBytes || options.command || new Uint8Array(), 'XFTP command');
  var block = options.privateKey
    ? encodeXftpWebAuthTransmission({
      sessionId: client.sessionId,
      corrId: options.corrId || new Uint8Array(),
      entityId: options.entityId || new Uint8Array(),
      commandBytes,
      privateKey: options.privateKey
    })
    : encodeXftpWebTransmission({
      sessionId: client.sessionId,
      corrId: options.corrId || new Uint8Array(),
      entityId: options.entityId || new Uint8Array(),
      commandBytes
    });
  var requestBody = options.body ? concatBytes(block, options.body) : block;
  var responseBody = await client.postBlock(requestBody, options.headers);
  if (responseBody.length < XFTP_WEB_BLOCK_SIZE) fail('XFTP_WEB_RESPONSE', 'XFTP web response is shorter than one block');
  var tx = decodeXftpWebBrokerTransmission(client.sessionId, responseBody.slice(0, XFTP_WEB_BLOCK_SIZE));
  if (tx.response.type === 'ERR') fail('XFTP_WEB_SERVER', 'XFTP web server returned ERR');
  return {
    ...tx,
    body: responseBody.slice(XFTP_WEB_BLOCK_SIZE)
  };
}

export async function pingXftpWeb(client) {
  var response = await sendXftpWebCommand(client, { commandBytes: encodeXftpWebPING() });
  if (response.response.type !== 'PONG') fail('XFTP_WEB_RESPONSE', 'XFTP web PING expected PONG');
  return response;
}

export async function createXftpWebFile(client, options = {}) {
  var response = await sendXftpWebCommand(client, {
    privateKey: options.privateKey,
    entityId: new Uint8Array(),
    commandBytes: encodeXftpWebFNEW(options.fileInfo, options.recipientKeys || [], options.auth || null)
  });
  if (response.response.type !== 'SIDS') fail('XFTP_WEB_RESPONSE', 'XFTP web FNEW expected SIDS');
  return response.response;
}

export async function putXftpWebFile(client, options = {}) {
  var response = await sendXftpWebCommand(client, {
    privateKey: options.privateKey,
    entityId: options.senderId,
    commandBytes: encodeXftpWebFPUT(),
    body: options.body || new Uint8Array()
  });
  if (response.response.type !== 'OK') fail('XFTP_WEB_RESPONSE', 'XFTP web FPUT expected OK');
  return response.response;
}

export async function getXftpWebFile(client, options = {}) {
  var dh = options.dhKey || generateX25519KeyPair(options.dhSeed);
  var response = await sendXftpWebCommand(client, {
    privateKey: options.privateKey,
    entityId: options.recipientId,
    commandBytes: encodeXftpWebFGET(dh.publicKey)
  });
  if (response.response.type !== 'FILE') fail('XFTP_WEB_RESPONSE', 'XFTP web FGET expected FILE');
  return {
    ...response.response,
    dhSecret: x25519SharedSecret(dh.secretKey, response.response.rcvDhKey),
    body: response.body
  };
}

export async function downloadXftpWebFileChunk(client, options = {}) {
  var downloaded = await getXftpWebFile(client, options);
  return {
    ...downloaded,
    plaintext: decryptXftpWebTransportChunk(
      downloaded.dhSecret,
      downloaded.nonce,
      downloaded.body,
      options.digest || options.expectedDigest || null
    )
  };
}

export async function deleteXftpWebFile(client, options = {}) {
  var response = await sendXftpWebCommand(client, {
    privateKey: options.privateKey,
    entityId: options.senderId,
    commandBytes: encodeXftpWebFDEL()
  });
  if (response.response.type !== 'OK') fail('XFTP_WEB_RESPONSE', 'XFTP web FDEL expected OK');
  return response.response;
}

const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');

function decodeXftpWebEd25519PrivateKeyDer(value) {
  var der = toBytes(value || new Uint8Array(), 'XFTP Ed25519 private key DER');
  if (der.length === 32) return der;
  if (der.length !== ED25519_PKCS8_PREFIX.length + 32) fail('XFTP_WEB_KEY', 'XFTP Ed25519 private key DER has invalid length');
  for (var i = 0; i < ED25519_PKCS8_PREFIX.length; i += 1) {
    if (der[i] !== ED25519_PKCS8_PREFIX[i]) fail('XFTP_WEB_KEY', 'XFTP Ed25519 private key DER has invalid prefix');
  }
  return der.slice(ED25519_PKCS8_PREFIX.length);
}

function xftpWebAddressFromClient(client, options = {}) {
  if (options.serverAddress) return String(options.serverAddress);
  var url = new URL(client.url);
  return formatXftpWebServerAddress({
    keyHash: client.keyHash,
    host: url.hostname,
    port: url.port || (url.protocol === 'http:' ? '80' : '443')
  });
}

function normalizedXftpWebServerAddress(address) {
  var parsed = parseXftpWebServerAddress(address);
  return {
    keyHash: parsed.keyHash,
    host: String(parsed.host || '').toLowerCase(),
    port: String(parsed.port || '443')
  };
}

function assertXftpWebReplicaServerMatchesClient(client, replica, options = {}) {
  if (options.allowReplicaServerMismatchForTests === true) return;
  var expected = normalizedXftpWebServerAddress(xftpWebAddressFromClient(client, options));
  var got = normalizedXftpWebServerAddress(replica.server);
  if (!equalBytes(got.keyHash, expected.keyHash) || got.host !== expected.host || got.port !== expected.port) {
    fail('XFTP_WEB_DESCRIPTION', 'XFTP replica server does not match the connected client');
  }
}

function readDescriptionLine(lines, index, pattern, label) {
  if (index >= lines.length) fail('XFTP_WEB_DESCRIPTION', label + ' is missing');
  var match = pattern.exec(lines[index]);
  if (!match) fail('XFTP_WEB_DESCRIPTION', label + ' is invalid');
  return match;
}

export function encodeXftpWebFileDescription(description) {
  var desc = normalizeXftpWebDescription(description);
  var lines = [
    'simplexWebXftpDescription: 1',
    'party: ' + desc.party,
    'size: ' + formatXftpWebDescriptionSize(desc.size),
    'digest: ' + encodeBase64UrlPadded(desc.digest),
    'key: ' + encodeBase64UrlPadded(desc.key),
    'nonce: ' + encodeBase64UrlPadded(desc.nonce),
    'chunkSize: ' + formatXftpWebDescriptionSize(desc.chunkSize || desc.chunks[0].chunkSize),
    'fileName: ' + encodeMaybeBase64UrlString(desc.fileName || 'file'),
    'fileExtra: ' + encodeMaybeBase64UrlString(desc.fileExtra),
    'chunks:'
  ];
  for (var chunk of sortDescriptionChunks(desc)) {
    lines.push('  - chunkNo: ' + safeInteger(chunk.chunkNo, 'XFTP chunk number', 1, 0xffffffff));
    lines.push('    offset: ' + safeInteger(chunk.offset || 0, 'XFTP chunk offset', 0, Number.MAX_SAFE_INTEGER));
    lines.push('    chunkSize: ' + formatXftpWebDescriptionSize(chunk.chunkSize));
    lines.push('    digest: ' + encodeBase64UrlPadded(chunk.digest));
    lines.push('    replicas:');
    for (var replica of chunk.replicas) {
      lines.push('      - server: ' + replica.server);
      lines.push('        replicaId: ' + encodeBase64UrlPadded(replica.replicaId));
      lines.push('        replicaKey: ' + encodeBase64UrlPadded(replica.replicaKey));
    }
  }
  return lines.join('\n') + '\n';
}

export function decodeXftpWebFileDescription(text) {
  var raw = String(text == null ? '' : text);
  if (!raw || raw.length > 1024 * 1024) fail('XFTP_WEB_DESCRIPTION', 'XFTP file description size is invalid');
  var lines = raw.split(/\r?\n/).filter((line) => line.trim() && !/^\s*#/.test(line));
  var i = 0;
  readDescriptionLine(lines, i++, /^simplexWebXftpDescription: 1$/, 'description marker');
  var party = readDescriptionLine(lines, i++, /^party: (recipient|sender)$/, 'description party')[1];
  var size = parseXftpWebDescriptionSize(readDescriptionLine(lines, i++, /^size: ([0-9]+(?:kb|mb|gb)?)$/i, 'description size')[1], 'XFTP description size');
  var digest = parseXftpWebDescriptionBytes(readDescriptionLine(lines, i++, /^digest: ([A-Za-z0-9_-]+={0,2})$/, 'description digest')[1], 'XFTP description digest', 64);
  var key = parseXftpWebDescriptionBytes(readDescriptionLine(lines, i++, /^key: ([A-Za-z0-9_-]+={0,2})$/, 'description key')[1], 'XFTP description key', 32);
  var nonce = parseXftpWebDescriptionBytes(readDescriptionLine(lines, i++, /^nonce: ([A-Za-z0-9_-]+={0,2})$/, 'description nonce')[1], 'XFTP description nonce', 24);
  var chunkSize = parseXftpWebDescriptionSize(readDescriptionLine(lines, i++, /^chunkSize: ([0-9]+(?:kb|mb|gb)?)$/i, 'description chunk size')[1], 'XFTP description chunk size');
  var fileName = decodeMaybeBase64UrlString(readDescriptionLine(lines, i++, /^fileName: ([A-Za-z0-9_-]+={0,2}|-)$/, 'description file name')[1], 'XFTP description file name');
  var fileExtra = decodeMaybeBase64UrlString(readDescriptionLine(lines, i++, /^fileExtra: ([A-Za-z0-9_-]+={0,2}|-)$/, 'description file extra')[1], 'XFTP description file extra');
  readDescriptionLine(lines, i++, /^chunks:$/, 'description chunks marker');
  var chunks = [];
  while (i < lines.length) {
    var chunkNo = safeInteger(readDescriptionLine(lines, i++, /^  - chunkNo: ([0-9]+)$/, 'chunk number')[1], 'XFTP chunk number', 1, 0xffffffff);
    var offset = safeInteger(readDescriptionLine(lines, i++, /^    offset: ([0-9]+)$/, 'chunk offset')[1], 'XFTP chunk offset', 0, Number.MAX_SAFE_INTEGER);
    var nextChunkSize = parseXftpWebDescriptionSize(readDescriptionLine(lines, i++, /^    chunkSize: ([0-9]+(?:kb|mb|gb)?)$/i, 'chunk size')[1], 'XFTP chunk size');
    var chunkDigest = parseXftpWebDescriptionBytes(readDescriptionLine(lines, i++, /^    digest: ([A-Za-z0-9_-]+={0,2})$/, 'chunk digest')[1], 'XFTP chunk digest', 32);
    readDescriptionLine(lines, i++, /^    replicas:$/, 'chunk replicas marker');
    var replicas = [];
    while (i < lines.length && /^      - server: /.test(lines[i])) {
      var server = readDescriptionLine(lines, i++, /^      - server: (xftp:\/\/[A-Za-z0-9_-]+={0,2}@[^:#,;\/\s]+(?::[0-9]+)?)$/, 'replica server')[1];
      parseXftpWebServerAddress(server);
      var replicaId = parseXftpWebDescriptionBytes(readDescriptionLine(lines, i++, /^        replicaId: ([A-Za-z0-9_-]+={0,2})$/, 'replica id')[1], 'XFTP replica id');
      var replicaKey = parseXftpWebDescriptionBytes(readDescriptionLine(lines, i++, /^        replicaKey: ([A-Za-z0-9_-]+={0,2})$/, 'replica key')[1], 'XFTP replica key');
      replicas.push({ server, replicaId, replicaKey });
    }
    chunks.push({ chunkNo, offset, chunkSize: nextChunkSize, digest: chunkDigest, replicas });
  }
  return normalizeXftpWebDescription({
    party,
    size,
    digest,
    key,
    nonce,
    chunkSize,
    fileName: safeXftpWebFileName(fileName || 'file'),
    fileExtra,
    chunks
  });
}

function validateXftpWebDescriptionChunkPlan(description) {
  var expectedOffset = 0;
  var sorted = [...description.chunks].sort((left, right) => left.chunkNo - right.chunkNo);
  for (var index = 0; index < sorted.length; index += 1) {
    var chunk = sorted[index];
    if (chunk.chunkNo !== index + 1) fail('XFTP_WEB_DESCRIPTION', 'XFTP chunk numbers must be contiguous');
    if (chunk.offset !== expectedOffset) fail('XFTP_WEB_DESCRIPTION', 'XFTP chunk offsets must be contiguous');
    expectedOffset += chunk.chunkSize;
  }
  if (expectedOffset !== description.size) fail('XFTP_WEB_DESCRIPTION', 'XFTP chunk sizes do not match the encrypted file size');
}

function normalizeXftpWebDescription(description) {
  if (typeof description === 'string') return decodeXftpWebFileDescription(description);
  var desc = description && typeof description === 'object' ? description : {};
  var party = String(desc.party || '').trim();
  if (party !== 'recipient' && party !== 'sender') fail('XFTP_WEB_DESCRIPTION', 'XFTP file description party is invalid');
  var chunks = Array.isArray(desc.chunks) ? desc.chunks : [];
  if (!chunks.length) fail('XFTP_WEB_DESCRIPTION', 'XFTP file description has no chunks');
  if (chunks.length > XFTP_WEB_MAX_DESCRIPTION_CHUNKS) fail('XFTP_WEB_DESCRIPTION', 'XFTP file description has too many chunks');
  var normalized = {
    party,
    size: safeInteger(desc.size, 'XFTP description size', 0, Number.MAX_SAFE_INTEGER),
    digest: toBytes(desc.digest || new Uint8Array(), 'XFTP description digest'),
    key: toBytes(desc.key || new Uint8Array(), 'XFTP description key'),
    nonce: toBytes(desc.nonce || new Uint8Array(), 'XFTP description nonce'),
    chunkSize: safeInteger(desc.chunkSize || chunks[0].chunkSize, 'XFTP description chunk size', 1, 0xffffffff),
    fileName: safeXftpWebFileName(desc.fileName || 'file'),
    fileExtra: desc.fileExtra == null ? null : String(desc.fileExtra),
    chunks: []
  };
  if (normalized.digest.length !== 64) fail('XFTP_WEB_DESCRIPTION', 'XFTP description digest has the wrong length');
  if (normalized.key.length !== 32) fail('XFTP_WEB_DESCRIPTION', 'XFTP description key has the wrong length');
  if (normalized.nonce.length !== 24) fail('XFTP_WEB_DESCRIPTION', 'XFTP description nonce has the wrong length');
  for (var chunk of chunks) {
    var replicas = Array.isArray(chunk.replicas) ? chunk.replicas : [];
    if (!replicas.length) fail('XFTP_WEB_DESCRIPTION', 'XFTP chunk has no replicas');
    if (replicas.length > XFTP_WEB_MAX_DESCRIPTION_REPLICAS) fail('XFTP_WEB_DESCRIPTION', 'XFTP chunk has too many replicas');
    var normalizedChunk = {
      chunkNo: safeInteger(chunk.chunkNo, 'XFTP chunk number', 1, 0xffffffff),
      offset: safeInteger(chunk.offset || 0, 'XFTP chunk offset', 0, Number.MAX_SAFE_INTEGER),
      chunkSize: safeInteger(chunk.chunkSize, 'XFTP chunk size', 1, 0xffffffff),
      digest: toBytes(chunk.digest || new Uint8Array(), 'XFTP chunk digest'),
      replicas: replicas.map((replica) => {
        var server = String(replica.server || '').trim();
        parseXftpWebServerAddress(server);
        var replicaId = toBytes(replica.replicaId || new Uint8Array(), 'XFTP replica id');
        var replicaKey = toBytes(replica.replicaKey || new Uint8Array(), 'XFTP replica key');
        if (!replicaId.length || replicaId.length > 255) fail('XFTP_WEB_DESCRIPTION', 'XFTP replica id length is invalid');
        if (replicaKey.length !== 32 && replicaKey.length !== ED25519_PKCS8_PREFIX.length + 32) {
          fail('XFTP_WEB_DESCRIPTION', 'XFTP replica key length is invalid');
        }
        return { server, replicaId, replicaKey };
      })
    };
    if (normalizedChunk.digest.length !== 32) fail('XFTP_WEB_DESCRIPTION', 'XFTP chunk digest has the wrong length');
    normalized.chunks.push(normalizedChunk);
  }
  validateXftpWebDescriptionChunkPlan(normalized);
  return normalized;
}

function firstReplica(chunk) {
  if (!Array.isArray(chunk.replicas) || !chunk.replicas.length) fail('XFTP_WEB_DESCRIPTION', 'XFTP chunk has no replicas');
  return chunk.replicas[0];
}

function sortDescriptionChunks(description) {
  return [...normalizeXftpWebDescription(description).chunks].sort((left, right) => left.chunkNo - right.chunkNo);
}

function sortUploadedXftpWebDeleteChunks(description) {
  var source = typeof description === 'string' ? normalizeXftpWebDescription(description) : (description && typeof description === 'object' ? description : {});
  if (source.party != null && String(source.party).trim() !== 'sender') {
    fail('XFTP_WEB_DESCRIPTION', 'XFTP delete requires a sender file description');
  }
  var chunks = Array.isArray(source.chunks) ? source.chunks : [];
  if (!chunks.length) fail('XFTP_WEB_DESCRIPTION', 'XFTP delete description has no chunks');
  return chunks.map((chunk) => ({
    ...chunk,
    chunkNo: safeInteger(chunk.chunkNo, 'XFTP chunk number', 1, 0xffffffff),
    replicas: (Array.isArray(chunk.replicas) ? chunk.replicas : []).map((replica) => {
      var replicaId = toBytes(replica.replicaId || new Uint8Array(), 'XFTP delete replica id');
      if (!replicaId.length || replicaId.length > 255) fail('XFTP_WEB_DESCRIPTION', 'XFTP delete replica id length is invalid');
      return {
        ...replica,
        replicaId,
        replicaKey: toBytes(replica.replicaKey || replica.privateKey || replica.privateKeyDer || new Uint8Array(), 'XFTP delete replica key')
      };
    })
  })).sort((left, right) => left.chunkNo - right.chunkNo);
}

export async function uploadXftpWebFile(client, source, options = {}) {
  var encryptedFile = encryptXftpWebFileEnvelope(source, options);
  var serverAddress = xftpWebAddressFromClient(client, options);
  var recipientChunks = [];
  var senderChunks = [];
  var uploadedSenderChunks = [];
  // Each encrypted file chunk gets its own sender/recipient signing key pair.
  // The recipient description carries only the recipient private key needed to
  // download; the sender description carries only the sender key needed to
  // delete.  The envelope key/nonce are returned for browser-side delivery
  // through the ratcheted chat channel; the XFTP server sees encrypted chunks.
  try {
    for (var spec of encryptedFile.chunkSpecs) {
      var chunkData = encryptedFile.encrypted.slice(spec.offset, spec.offset + spec.chunkSize);
      var chunkDigest = sha256Hash(chunkData);
      var sender = generateEd25519KeyPair(options.senderSeeds && options.senderSeeds[spec.chunkNo - 1]);
      var recipient = generateEd25519KeyPair(options.recipientSeeds && options.recipientSeeds[spec.chunkNo - 1]);
      var created = await createXftpWebFile(client, {
        privateKey: sender.secretKey,
        fileInfo: {
          sndKey: sender.publicKeyDer,
          size: chunkData.length,
          digest: chunkDigest
        },
        recipientKeys: [recipient.publicKeyDer]
      });
      var senderRecord = {
        chunkNo: spec.chunkNo,
        offset: spec.offset,
        chunkSize: chunkData.length,
        digest: chunkDigest,
        replicas: [{
          server: serverAddress,
          replicaId: created.senderId,
          replicaKey: encodePrivateKeyDer('Ed25519', sender.secretKey)
        }]
      };
      try {
        await putXftpWebFile(client, {
          privateKey: sender.secretKey,
          senderId: created.senderId,
          body: chunkData
        });
      } catch (error) {
        try {
          await deleteUploadedXftpWebFile(client, { chunks: [senderRecord] });
        } catch (_cleanupError) {}
        throw error;
      }
      uploadedSenderChunks.push(senderRecord);
      var recipientRecord = {
        chunkNo: spec.chunkNo,
        offset: spec.offset,
        chunkSize: chunkData.length,
        digest: chunkDigest,
        replicas: [{
          server: serverAddress,
          replicaId: created.recipientIds[0],
          replicaKey: encodePrivateKeyDer('Ed25519', recipient.secretKey)
        }]
      };
      recipientChunks.push(recipientRecord);
      senderChunks.push(senderRecord);
    }
  } catch (error) {
    for (var cleanup of uploadedSenderChunks.reverse()) {
      try {
        await deleteUploadedXftpWebFile(client, { chunks: [cleanup] });
      } catch (_cleanupError) {}
    }
    throw error;
  }
  var base = {
    size: encryptedFile.encryptedSize,
    digest: encryptedFile.digest,
    key: encryptedFile.key,
    nonce: encryptedFile.nonce,
    chunkSize: encryptedFile.chunkSizes[0],
    fileName: encryptedFile.header.fileName,
    fileExtra: encryptedFile.header.fileExtra
  };
  return {
    ...encryptedFile,
    recipientDescription: {
      ...base,
      party: 'recipient',
      chunks: recipientChunks
    },
    senderDescription: {
      ...base,
      party: 'sender',
      chunks: senderChunks
    }
  };
}

export async function downloadXftpWebFile(client, description, options = {}) {
  var desc = normalizeXftpWebDescription(description);
  if (desc.party !== 'recipient') fail('XFTP_WEB_DESCRIPTION', 'XFTP download requires a recipient file description');
  var encryptedChunks = [];
  var totalSize = 0;
  // Download starts from the recipient description: authenticate each server
  // response, verify each encrypted chunk digest, then verify and decrypt the
  // whole file envelope only after all chunks have arrived.
  for (var chunk of sortDescriptionChunks(desc)) {
    var replica = options.chooseReplica ? options.chooseReplica(chunk) : firstReplica(chunk);
    assertXftpWebReplicaServerMatchesClient(client, replica, options);
    var seed = decodeXftpWebEd25519PrivateKeyDer(replica.replicaKey || replica.privateKey || replica.privateKeyDer);
    var downloaded = await downloadXftpWebFileChunk(client, {
      privateKey: seed,
      recipientId: replica.replicaId,
      digest: chunk.digest
    });
    if (chunk.chunkSize != null && downloaded.plaintext.length !== safeInteger(chunk.chunkSize, 'XFTP chunk size', 0, 0xffffffff)) {
      fail('XFTP_WEB_SIZE', 'XFTP downloaded chunk size mismatch');
    }
    encryptedChunks.push(downloaded.plaintext);
    totalSize += downloaded.plaintext.length;
  }
  if (totalSize !== safeInteger(desc.size, 'XFTP encrypted file size', 0, Number.MAX_SAFE_INTEGER)) {
    fail('XFTP_WEB_SIZE', 'XFTP downloaded file size mismatch');
  }
  var decrypted = decryptXftpWebFileEnvelope(encryptedChunks, {
    key: desc.key,
    nonce: desc.nonce,
    digest: desc.digest,
    size: desc.size
  });
  return {
    ...decrypted,
    encryptedChunks
  };
}

export async function deleteUploadedXftpWebFile(client, senderDescription, options = {}) {
  for (var chunk of sortUploadedXftpWebDeleteChunks(senderDescription)) {
    var replica = options.chooseReplica ? options.chooseReplica(chunk) : firstReplica(chunk);
    assertXftpWebReplicaServerMatchesClient(client, replica, options);
    var seed = decodeXftpWebEd25519PrivateKeyDer(replica.replicaKey || replica.privateKey || replica.privateKeyDer);
    await deleteXftpWebFile(client, {
      privateKey: seed,
      senderId: replica.replicaId
    });
  }
}

export default {
  BrowserXftpWebClientError,
  XFTP_WEB_BLOCK_SIZE,
  XFTP_WEB_FILE_AUTH_TAG_SIZE,
  XFTP_WEB_FILE_SIZE_PREFIX_LENGTH,
  XFTP_WEB_HUGE_CHUNK_SIZE,
  XFTP_WEB_LARGE_CHUNK_SIZE,
  XFTP_WEB_MAX_DESCRIPTION_CHUNKS,
  XFTP_WEB_MAX_DESCRIPTION_REPLICAS,
  XFTP_WEB_MEDIUM_CHUNK_SIZE,
  XFTP_WEB_SMALL_CHUNK_SIZE,
  connectBrowserXftpWebClient,
  createXftpWebFile,
  decodeXftpWebBrokerTransmission,
  decodeXftpWebFileDescription,
  decodeXftpWebFileHeader,
  decodeXftpWebResponse,
  decodeXftpWebServerHandshake,
  decodeXftpWebTransmission,
  decryptXftpWebFileEnvelope,
  decryptXftpWebTransportChunk,
  deleteUploadedXftpWebFile,
  deleteXftpWebFile,
  downloadXftpWebFile,
  downloadXftpWebFileChunk,
  encodeXftpWebFileDescription,
  encodeXftpWebFileHeader,
  encodeXftpWebAuthTransmission,
  encodeXftpWebClientHandshake,
  encodeXftpWebClientHello,
  encodeXftpWebFADD,
  encodeXftpWebFDEL,
  encodeXftpWebFGET,
  encodeXftpWebFNEW,
  encodeXftpWebFPUT,
  encodeXftpWebFileInfo,
  encodeXftpWebPING,
  encodeXftpWebSignedKeyForTests,
  encodeXftpWebTransmission,
  encryptXftpWebFileEnvelope,
  encryptXftpWebTransportChunk,
  formatXftpWebServerAddress,
  getXftpWebFile,
  normalizeXftpWebUrl,
  parseXftpWebServerAddress,
  pingXftpWeb,
  prepareXftpWebChunkSizes,
  prepareXftpWebChunkSpecs,
  putXftpWebFile,
  sendXftpWebCommand,
  uploadXftpWebFile,
  verifyXftpWebIdentityProof
};
