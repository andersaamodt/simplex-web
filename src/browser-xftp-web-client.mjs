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

import {
  asciiBytes,
  concatBytes,
  decodeBase64Url,
  decodePublicKeyDer,
  ed25519Sign,
  ed25519Verify,
  encodeBase64Url,
  encodeLargeBytes,
  encodePublicKeyDer,
  encodeSmallBytes,
  encodeWord16,
  encodeWord32,
  equalBytes,
  generateX25519KeyPair,
  padBlock,
  randomBytes32,
  sha256Hash,
  toBytes,
  unpadBlock,
  x25519SharedSecret
} from './browser-smp-core.mjs';

export const XFTP_WEB_BLOCK_SIZE = 16384;
export const XFTP_WEB_INITIAL_VERSION = 1;
export const XFTP_WEB_AUTH_COMMANDS_VERSION = 2;
export const XFTP_WEB_CURRENT_VERSION = 3;

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

export async function deleteXftpWebFile(client, options = {}) {
  var response = await sendXftpWebCommand(client, {
    privateKey: options.privateKey,
    entityId: options.senderId,
    commandBytes: encodeXftpWebFDEL()
  });
  if (response.response.type !== 'OK') fail('XFTP_WEB_RESPONSE', 'XFTP web FDEL expected OK');
  return response.response;
}

export default {
  BrowserXftpWebClientError,
  XFTP_WEB_BLOCK_SIZE,
  connectBrowserXftpWebClient,
  createXftpWebFile,
  decodeXftpWebBrokerTransmission,
  decodeXftpWebResponse,
  decodeXftpWebServerHandshake,
  decodeXftpWebTransmission,
  deleteXftpWebFile,
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
  formatXftpWebServerAddress,
  getXftpWebFile,
  normalizeXftpWebUrl,
  parseXftpWebServerAddress,
  pingXftpWeb,
  putXftpWebFile,
  sendXftpWebCommand,
  verifyXftpWebIdentityProof
};
