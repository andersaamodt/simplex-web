// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser-native SMP protocol primitives.
//
// This module is deliberately small and explicit.  It does not talk to the
// plaintext command bridge, and it does not send plaintext to a website bridge.
// It implements the low-level SimpleX Messaging Protocol (SMP) pieces that a
// browser transport needs before a full agent/contact layer can be built:
//
// - byte/string encodings used by simplexmq's Haskell `Encoding` instances
// - `smp://` queue URI parsing
// - fixed-size 16384-byte transport block padding
// - SMP v3 single-transmission and SMP v4+ batched block framing
// - command/response codecs for SMP queue operations
// - Ed25519 signatures, X25519/X448 DH, XSalsa20-Poly1305, AES-GCM, and SHA-256
//
// The code favors readable checks over cleverness because protocol code is a
// trust boundary.  Every helper either returns bytes of one exact wire shape or
// throws `SimplexSmpProtocolError` with a stable code.

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { x448 } from '@noble/curves/ed448.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const SMP_BLOCK_SIZE = 16384;
export const SMP_MAX_MESSAGE_LENGTH = 16088;
export const SMP_MAX_RCV_MESSAGE_LENGTH = SMP_MAX_MESSAGE_LENGTH + 16;
export const SMP_E2E_ENC_CONFIRMATION_LENGTH = 15936;
export const SMP_E2E_ENC_MESSAGE_LENGTH = 16032;
export const SMP_BROWSER_MIN_VERSION = 3;
export const SMP_BROWSER_MAX_VERSION = 6;
export const SMP_DEFAULT_PORT = '5223';

export class SimplexSmpProtocolError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SimplexSmpProtocolError';
    this.code = code;
  }
}

function protocolError(code, message) {
  return new SimplexSmpProtocolError(code, message);
}

function fail(code, message) {
  throw protocolError(code, message);
}

function isBytes(value) {
  return value instanceof Uint8Array;
}

function copyBytes(value) {
  return new Uint8Array(value);
}

export function utf8Bytes(value) {
  return new TextEncoder().encode(String(value == null ? '' : value));
}

export function utf8Text(bytes) {
  return new TextDecoder('utf-8', { fatal: true }).decode(toBytes(bytes, 'utf8 bytes'));
}

export function asciiBytes(value) {
  var text = String(value == null ? '' : value);
  var out = new Uint8Array(text.length);
  for (var i = 0; i < text.length; i += 1) {
    var code = text.charCodeAt(i);
    if (code > 0x7f) fail('SMP_ASCII', 'SMP ASCII text contains a non-ASCII character');
    out[i] = code;
  }
  return out;
}

export function asciiText(bytes) {
  var input = toBytes(bytes, 'ASCII bytes');
  var out = '';
  for (var i = 0; i < input.length; i += 1) {
    if (input[i] > 0x7f) fail('SMP_ASCII', 'SMP ASCII bytes contain a non-ASCII byte');
    out += String.fromCharCode(input[i]);
  }
  return out;
}

export function toBytes(value, label = 'value') {
  // Protocol functions only operate on byte arrays.  Accepting strings here is
  // intentionally UTF-8, not Latin-1, so callers cannot accidentally smuggle
  // browser string code units into binary fields.
  if (isBytes(value)) return copyBytes(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  if (typeof value === 'string') return utf8Bytes(value);
  fail('SMP_BYTES', label + ' must be bytes or a string');
}

export function concatBytes(...chunks) {
  var normalized = chunks.map((chunk, index) => toBytes(chunk, 'chunk ' + index));
  var length = normalized.reduce((sum, chunk) => sum + chunk.length, 0);
  var out = new Uint8Array(length);
  var offset = 0;
  for (var chunk of normalized) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function equalBytes(a, b) {
  var left = toBytes(a, 'left bytes');
  var right = toBytes(b, 'right bytes');
  if (left.length !== right.length) return false;
  var diff = 0;
  for (var i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

function assertSafeInteger(value, label, min, max) {
  var next = Number(value);
  if (!Number.isSafeInteger(next) || next < min || next > max) {
    fail('SMP_RANGE', label + ' is outside the supported range');
  }
  return next;
}

export function encodeWord16(value) {
  var n = assertSafeInteger(value, 'word16', 0, 0xffff);
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

export function decodeWord16(bytes, offset = 0) {
  var input = toBytes(bytes, 'word16 bytes');
  if (offset < 0 || offset + 2 > input.length) fail('SMP_TRUNCATED', 'word16 is truncated');
  return (input[offset] << 8) | input[offset + 1];
}

export function encodeWord32(value) {
  var n = assertSafeInteger(value, 'word32', 0, 0xffffffff);
  return new Uint8Array([
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff
  ]);
}

export function decodeWord32(bytes, offset = 0) {
  var input = toBytes(bytes, 'word32 bytes');
  if (offset < 0 || offset + 4 > input.length) fail('SMP_TRUNCATED', 'word32 is truncated');
  return (
    input[offset] * 0x1000000 +
    ((input[offset + 1] << 16) | (input[offset + 2] << 8) | input[offset + 3])
  );
}

export function encodeWord64(value) {
  var n = typeof value === 'bigint' ? value : BigInt(assertSafeInteger(value, 'word64', 0, Number.MAX_SAFE_INTEGER));
  if (n < 0n || n > 0xffffffffffffffffn) fail('SMP_RANGE', 'word64 is outside the supported range');
  var out = new Uint8Array(8);
  for (var i = 7; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function decodeWord64(bytes, offset = 0) {
  var input = toBytes(bytes, 'word64 bytes');
  if (offset < 0 || offset + 8 > input.length) fail('SMP_TRUNCATED', 'word64 is truncated');
  var n = 0n;
  for (var i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(input[offset + i]);
  return n;
}

export function encodeSmallBytes(value) {
  var bytes = toBytes(value, 'small bytes');
  if (bytes.length > 255) fail('SMP_LENGTH', 'small byte string is longer than 255 bytes');
  return concatBytes(new Uint8Array([bytes.length]), bytes);
}

export function encodeLargeBytes(value) {
  var bytes = toBytes(value, 'large bytes');
  if (bytes.length > 0xffff) fail('SMP_LENGTH', 'large byte string is longer than 65535 bytes');
  return concatBytes(encodeWord16(bytes.length), bytes);
}

class ByteReader {
  constructor(bytes, label = 'SMP bytes') {
    this.bytes = toBytes(bytes, label);
    this.offset = 0;
    this.label = label;
  }

  remaining() {
    return this.bytes.length - this.offset;
  }

  eof() {
    return this.offset === this.bytes.length;
  }

  take(length, label = 'field') {
    var n = assertSafeInteger(length, label + ' length', 0, Number.MAX_SAFE_INTEGER);
    if (this.offset + n > this.bytes.length) fail('SMP_TRUNCATED', label + ' is truncated');
    var out = this.bytes.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  takeByte(label = 'byte') {
    if (this.offset >= this.bytes.length) fail('SMP_TRUNCATED', label + ' is missing');
    return this.bytes[this.offset++];
  }

  takeSmall(label = 'small field') {
    return this.take(this.takeByte(label + ' length'), label);
  }

  takeLarge(label = 'large field') {
    var length = decodeWord16(this.take(2, label + ' length'));
    return this.take(length, label);
  }

  takeTail() {
    return this.take(this.remaining(), 'tail');
  }

  expectSpace(context) {
    var next = this.takeByte(context + ' separator');
    if (next !== 0x20) fail('SMP_SYNTAX', context + ' must be followed by a space');
  }

  takeToken(label = 'token') {
    var start = this.offset;
    while (this.offset < this.bytes.length && this.bytes[this.offset] !== 0x20) {
      this.offset += 1;
    }
    if (this.offset === start) fail('SMP_SYNTAX', label + ' is empty');
    return asciiText(this.bytes.slice(start, this.offset));
  }

  assertDone(context) {
    if (!this.eof()) fail('SMP_SYNTAX', context + ' has trailing bytes');
  }
}

function parseCommandTag(bytes) {
  var reader = new ByteReader(bytes, 'SMP command');
  var tag = reader.takeToken('command tag');
  var params = reader.eof() ? new Uint8Array() : (reader.expectSpace('command tag'), reader.takeTail());
  return { tag, params };
}

function encodeBoolFlag(value) {
  return asciiBytes(value ? 'T' : 'F');
}

function parseMsgFlags(params) {
  var reader = new ByteReader(params, 'SEND parameters');
  var notification = reader.takeByte('notification flag');
  if (notification !== 0x54 && notification !== 0x46) {
    fail('SMP_SYNTAX', 'SEND notification flag must be T or F');
  }
  while (!reader.eof()) {
    var b = reader.takeByte('SEND flag byte');
    if (b === 0x20) return { notification: notification === 0x54, body: reader.takeTail() };
  }
  fail('SMP_SYNTAX', 'SEND body separator is missing');
}

export function encodeMsgFlags(flags = {}) {
  return encodeBoolFlag(flags.notification === true);
}

export function encodeCommand(version, command) {
  var v = normalizeVersion(version);
  var cmd = command && typeof command === 'object' ? command : {};
  switch (String(cmd.type || '').toUpperCase()) {
    case 'NEW':
      return concatBytes('NEW ', encodeSmallBytes(cmd.rcvPublicVerifyKey), encodeSmallBytes(cmd.rcvPublicDhKey));
    case 'SUB':
      return asciiBytes('SUB');
    case 'KEY':
      return concatBytes('KEY ', encodeSmallBytes(cmd.sndPublicVerifyKey));
    case 'NKEY':
      return concatBytes('NKEY ', encodeSmallBytes(cmd.ntfPublicVerifyKey), encodeSmallBytes(cmd.rcvNtfPublicDhKey));
    case 'NDEL':
      return asciiBytes('NDEL');
    case 'GET':
      return asciiBytes('GET');
    case 'ACK':
      return v === 1 ? asciiBytes('ACK') : concatBytes('ACK ', encodeSmallBytes(cmd.msgId || new Uint8Array()));
    case 'OFF':
      return asciiBytes('OFF');
    case 'DEL':
      return asciiBytes('DEL');
    case 'SEND':
      return concatBytes('SEND ', encodeMsgFlags(cmd.flags), ' ', toBytes(cmd.body || new Uint8Array(), 'SEND body'));
    case 'PING':
      return asciiBytes('PING');
    case 'NSUB':
      return asciiBytes('NSUB');
    default:
      fail('SMP_COMMAND', 'unsupported SMP command type');
  }
}

export function parseCommand(version, bytes) {
  var v = normalizeVersion(version);
  var parsed = parseCommandTag(bytes);
  var reader = new ByteReader(parsed.params, parsed.tag + ' parameters');
  switch (parsed.tag) {
    case 'NEW': {
      var rcvPublicVerifyKey = reader.takeSmall('recipient signature public key');
      var rcvPublicDhKey = reader.takeSmall('recipient DH public key');
      reader.assertDone('NEW');
      return { type: 'NEW', rcvPublicVerifyKey, rcvPublicDhKey };
    }
    case 'SUB':
      reader.assertDone('SUB');
      return { type: 'SUB' };
    case 'KEY': {
      var sndPublicVerifyKey = reader.takeSmall('sender signature public key');
      reader.assertDone('KEY');
      return { type: 'KEY', sndPublicVerifyKey };
    }
    case 'NKEY': {
      var ntfPublicVerifyKey = reader.takeSmall('notifier signature public key');
      var rcvNtfPublicDhKey = reader.takeSmall('recipient notification DH public key');
      reader.assertDone('NKEY');
      return { type: 'NKEY', ntfPublicVerifyKey, rcvNtfPublicDhKey };
    }
    case 'NDEL':
      reader.assertDone('NDEL');
      return { type: 'NDEL' };
    case 'GET':
      reader.assertDone('GET');
      return { type: 'GET' };
    case 'ACK':
      if (v === 1) {
        reader.assertDone('ACK');
        return { type: 'ACK', msgId: new Uint8Array() };
      }
      var msgId = reader.takeSmall('message id');
      reader.assertDone('ACK');
      return { type: 'ACK', msgId };
    case 'OFF':
      reader.assertDone('OFF');
      return { type: 'OFF' };
    case 'DEL':
      reader.assertDone('DEL');
      return { type: 'DEL' };
    case 'SEND': {
      var sent = parseMsgFlags(parsed.params);
      return { type: 'SEND', flags: { notification: sent.notification }, body: sent.body };
    }
    case 'PING':
      reader.assertDone('PING');
      return { type: 'PING' };
    case 'NSUB':
      reader.assertDone('NSUB');
      return { type: 'NSUB' };
    default:
      fail('SMP_COMMAND', 'unknown SMP command tag');
  }
}

export function encodeBrokerMessage(version, message) {
  var v = normalizeVersion(version);
  var msg = message && typeof message === 'object' ? message : {};
  switch (String(msg.type || '').toUpperCase()) {
    case 'IDS':
      return concatBytes('IDS ', encodeSmallBytes(msg.rcvId), encodeSmallBytes(msg.sndId), encodeSmallBytes(msg.rcvPublicDhKey));
    case 'MSG':
      if (v === 1) {
        return concatBytes('MSG ', encodeSmallBytes(msg.msgId), encodeWord64(msg.timestamp || 0), toBytes(msg.body || new Uint8Array(), 'message body'));
      }
      if (v === 2) {
        return concatBytes('MSG ', encodeSmallBytes(msg.msgId), encodeWord64(msg.timestamp || 0), encodeMsgFlags(msg.flags), ' ', toBytes(msg.body || new Uint8Array(), 'message body'));
      }
      return concatBytes('MSG ', encodeSmallBytes(msg.msgId), toBytes(msg.body || new Uint8Array(), 'message body'));
    case 'NID':
      return concatBytes('NID ', encodeSmallBytes(msg.notifierId), encodeSmallBytes(msg.rcvNtfPublicDhKey));
    case 'NMSG':
      return concatBytes('NMSG ', toBytes(msg.nonce, 'notification nonce'), encodeSmallBytes(msg.meta));
    case 'END':
      return asciiBytes('END');
    case 'OK':
      return asciiBytes('OK');
    case 'ERR':
      return concatBytes('ERR ', encodeErrorType(msg.error || 'INTERNAL'));
    case 'PONG':
      return asciiBytes('PONG');
    default:
      fail('SMP_BROKER_MESSAGE', 'unsupported SMP broker message type');
  }
}

export function parseBrokerMessage(version, bytes) {
  var v = normalizeVersion(version);
  var parsed = parseCommandTag(bytes);
  var reader = new ByteReader(parsed.params, parsed.tag + ' parameters');
  switch (parsed.tag) {
    case 'IDS': {
      var rcvId = reader.takeSmall('recipient queue id');
      var sndId = reader.takeSmall('sender queue id');
      var rcvPublicDhKey = reader.takeSmall('server DH public key');
      reader.assertDone('IDS');
      return { type: 'IDS', rcvId, sndId, rcvPublicDhKey };
    }
    case 'MSG': {
      var msgId = reader.takeSmall('message id');
      if (v === 1) {
        var timestampV1 = decodeWord64(reader.take(8, 'message timestamp'));
        return { type: 'MSG', msgId, timestamp: timestampV1, flags: { notification: false }, body: reader.takeTail() };
      }
      if (v === 2) {
        var timestampV2 = decodeWord64(reader.take(8, 'message timestamp'));
        var flags = reader.takeByte('message notification flag');
        if (flags !== 0x54 && flags !== 0x46) fail('SMP_SYNTAX', 'MSG notification flag must be T or F');
        reader.expectSpace('MSG flags');
        return { type: 'MSG', msgId, timestamp: timestampV2, flags: { notification: flags === 0x54 }, body: reader.takeTail() };
      }
      return { type: 'MSG', msgId, timestamp: 0n, flags: { notification: false }, body: reader.takeTail() };
    }
    case 'NID': {
      var notifierId = reader.takeSmall('notifier id');
      var rcvNtfPublicDhKey = reader.takeSmall('server notification DH public key');
      reader.assertDone('NID');
      return { type: 'NID', notifierId, rcvNtfPublicDhKey };
    }
    case 'NMSG': {
      var nonce = reader.take(24, 'notification nonce');
      var meta = reader.takeSmall('encrypted notification metadata');
      reader.assertDone('NMSG');
      return { type: 'NMSG', nonce, meta };
    }
    case 'END':
      reader.assertDone('END');
      return { type: 'END' };
    case 'OK':
      reader.assertDone('OK');
      return { type: 'OK' };
    case 'ERR':
      return { type: 'ERR', error: parseErrorType(parsed.params) };
    case 'PONG':
      reader.assertDone('PONG');
      return { type: 'PONG' };
    default:
      fail('SMP_BROKER_MESSAGE', 'unknown SMP broker message tag');
  }
}

export function encodeErrorType(error) {
  if (typeof error === 'string') return asciiBytes(error);
  var value = error && typeof error === 'object' ? error : {};
  if (value.type === 'CMD') return asciiBytes('CMD ' + String(value.commandError || 'SYNTAX'));
  return asciiBytes(String(value.type || 'INTERNAL'));
}

export function parseErrorType(bytes) {
  var text = asciiText(bytes).trim();
  if (!text) fail('SMP_SYNTAX', 'ERR response is empty');
  if (text.startsWith('CMD ')) return { type: 'CMD', commandError: text.slice(4).trim() || 'SYNTAX' };
  return { type: text };
}

function normalizeVersion(version) {
  return assertSafeInteger(version, 'SMP version', 1, 0xffff);
}

export function encodeTransmission(version, sessionId, transmission) {
  var tx = transmission && typeof transmission === 'object' ? transmission : {};
  var commandBytes = tx.commandBytes
    ? toBytes(tx.commandBytes, 'command bytes')
    : encodeCommand(version, tx.command || tx);
  return concatBytes(
    encodeSmallBytes(sessionId || new Uint8Array()),
    encodeSmallBytes(tx.corrId || new Uint8Array()),
    encodeSmallBytes(tx.queueId || new Uint8Array()),
    commandBytes
  );
}

export function signTransmission(signedBytes, privateKey) {
  var key = normalizeEd25519SecretKey(privateKey);
  return ed25519.sign(toBytes(signedBytes, 'signed transmission'), key);
}

export function verifyTransmissionSignature(signedBytes, signature, publicKey) {
  return ed25519.verify(
    toBytes(signature, 'signature'),
    toBytes(signedBytes, 'signed transmission'),
    normalizeEd25519PublicKey(publicKey)
  );
}

export function encodeSignedTransmission(version, sessionId, transmission) {
  var tx = transmission && typeof transmission === 'object' ? transmission : {};
  var signed = encodeTransmission(version, sessionId, tx);
  var signature = tx.privateKey
    ? signTransmission(signed, tx.privateKey)
    : toBytes(tx.signature || new Uint8Array(), 'signature');
  return { signed, bytes: concatBytes(encodeSmallBytes(signature), signed), signature };
}

export function parseSignedTransmission(version, bytes, options = {}) {
  var reader = new ByteReader(bytes, 'signed transmission');
  var signature = reader.takeSmall('signature');
  var signed = reader.takeTail();
  var signedReader = new ByteReader(signed, 'signed transmission body');
  var sessionId = signedReader.takeSmall('session id');
  var corrId = signedReader.takeSmall('correlation id');
  var queueId = signedReader.takeSmall('queue id');
  var commandBytes = signedReader.takeTail();
  var parsed = {
    signature,
    signed,
    sessionId,
    corrId,
    queueId,
    commandBytes
  };
  if (options.kind === 'broker') {
    parsed.message = parseBrokerMessage(version, commandBytes);
  } else if (options.kind !== 'raw') {
    parsed.command = parseCommand(version, commandBytes);
  }
  return parsed;
}

export function padBlock(payload, paddedLength = SMP_BLOCK_SIZE) {
  var body = toBytes(payload, 'block payload');
  var size = assertSafeInteger(paddedLength, 'padded length', 2, 0xffff);
  var padLength = size - body.length - 2;
  if (padLength < 0) fail('SMP_LARGE_MSG', 'payload does not fit in padded block');
  var out = new Uint8Array(size);
  out.set(encodeWord16(body.length), 0);
  out.set(body, 2);
  out.fill(0x23, 2 + body.length);
  return out;
}

export function unpadBlock(block, paddedLength = SMP_BLOCK_SIZE) {
  var input = toBytes(block, 'padded block');
  var size = assertSafeInteger(paddedLength, 'padded length', 2, 0xffff);
  if (input.length !== size) fail('SMP_BAD_BLOCK', 'padded block has the wrong size');
  var length = decodeWord16(input, 0);
  if (length > input.length - 2) fail('SMP_BAD_BLOCK', 'padded block length is invalid');
  for (var i = 2 + length; i < input.length; i += 1) {
    if (input[i] !== 0x23) fail('SMP_BAD_BLOCK', 'padded block contains non-padding bytes');
  }
  return input.slice(2, 2 + length);
}

export function encodeTransportBlock(version, signedTransmissions) {
  var v = normalizeVersion(version);
  var transmissions = Array.isArray(signedTransmissions) ? signedTransmissions : [signedTransmissions];
  if (!transmissions.length) fail('SMP_BAD_BLOCK', 'transport block requires at least one transmission');
  var encoded = transmissions.map((tx) => toBytes(tx && tx.bytes ? tx.bytes : tx, 'signed transmission'));
  if (v >= 4) {
    if (encoded.length > 255) fail('SMP_BAD_BLOCK', 'SMP v4 batch cannot contain more than 255 transmissions');
    var body = concatBytes(new Uint8Array([encoded.length]), ...encoded.map(encodeLargeBytes));
    return padBlock(body, SMP_BLOCK_SIZE);
  }
  if (encoded.length !== 1) fail('SMP_BAD_BLOCK', 'SMP v3 transport blocks contain exactly one transmission');
  return padBlock(encoded[0], SMP_BLOCK_SIZE);
}

export function decodeTransportBlock(version, block, options = {}) {
  var v = normalizeVersion(version);
  var body = unpadBlock(block, SMP_BLOCK_SIZE);
  if (v >= 4) {
    var reader = new ByteReader(body, 'SMP v4 transport block');
    var count = reader.takeByte('transmission count');
    if (count < 1) fail('SMP_BAD_BLOCK', 'SMP v4 transport block has an empty batch');
    var transmissions = [];
    for (var i = 0; i < count; i += 1) {
      transmissions.push(parseSignedTransmission(v, reader.takeLarge('batched transmission'), options));
    }
    reader.assertDone('SMP v4 transport block');
    return transmissions;
  }
  return [parseSignedTransmission(v, body, options)];
}

export function encodeServerHandshake(handshake) {
  var hs = handshake && typeof handshake === 'object' ? handshake : {};
  return concatBytes(
    encodeWord16(assertSafeInteger(hs.minVersion, 'server min version', 1, 0xffff)),
    encodeWord16(assertSafeInteger(hs.maxVersion, 'server max version', 1, 0xffff)),
    encodeSmallBytes(hs.sessionId || new Uint8Array())
  );
}

export function parseServerHandshake(bytes) {
  var reader = new ByteReader(bytes, 'server handshake');
  var minVersion = decodeWord16(reader.take(2, 'server min version'));
  var maxVersion = decodeWord16(reader.take(2, 'server max version'));
  if (minVersion > maxVersion) fail('SMP_HANDSHAKE', 'server version range is invalid');
  var sessionId = reader.takeSmall('server session id');
  reader.assertDone('server handshake');
  return { minVersion, maxVersion, sessionId };
}

export function chooseCompatibleVersion(serverRange, clientRange = {}) {
  var serverMin = assertSafeInteger(serverRange.minVersion, 'server min version', 1, 0xffff);
  var serverMax = assertSafeInteger(serverRange.maxVersion, 'server max version', 1, 0xffff);
  var clientMin = assertSafeInteger(clientRange.minVersion || SMP_BROWSER_MIN_VERSION, 'client min version', 1, 0xffff);
  var clientMax = assertSafeInteger(clientRange.maxVersion || SMP_BROWSER_MAX_VERSION, 'client max version', 1, 0xffff);
  var version = Math.min(serverMax, clientMax);
  if (version < serverMin || version < clientMin) fail('SMP_HANDSHAKE', 'SMP version ranges are incompatible');
  return version;
}

export function encodeClientHandshake(handshake) {
  var hs = handshake && typeof handshake === 'object' ? handshake : {};
  return concatBytes(
    encodeWord16(assertSafeInteger(hs.version, 'client version', 1, 0xffff)),
    encodeSmallBytes(hs.keyHash || new Uint8Array())
  );
}

export function parseClientHandshake(bytes) {
  var reader = new ByteReader(bytes, 'client handshake');
  var version = decodeWord16(reader.take(2, 'client version'));
  var keyHash = reader.takeSmall('server key hash');
  reader.assertDone('client handshake');
  return { version, keyHash };
}

export function encodeBase64Url(bytes) {
  var input = toBytes(bytes, 'base64url bytes');
  var text = '';
  for (var i = 0; i < input.length; i += 1) text += String.fromCharCode(input[i]);
  var base64 = typeof btoa === 'function'
    ? btoa(text)
    : Buffer.from(input).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function decodeBase64Url(value, label = 'base64url value') {
  var text = String(value == null ? '' : value).trim();
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(text)) fail('SMP_BASE64URL', label + ' is not base64url');
  var base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  try {
    if (typeof atob === 'function') {
      var binary = atob(base64);
      var out = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
      return out;
    }
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } catch (_error) {
    fail('SMP_BASE64URL', label + ' is not valid base64url');
  }
}

export function parseProtocolServer(value) {
  var text = String(value == null ? '' : value).trim();
  var match = /^(smp|ntf):\/\/([A-Za-z0-9_-]+={0,2})@([^:#,;\/\s]+)(?::([0-9]+))?$/.exec(text);
  if (!match) fail('SMP_URI', 'protocol server must be smp:// or ntf:// with keyHash@host[:port]');
  var port = match[4] || '';
  if (port) assertSafeInteger(port, 'server port', 1, 65535);
  return {
    scheme: match[1],
    keyHash: decodeBase64Url(match[2], 'server identity hash'),
    host: match[3],
    port
  };
}

export function formatProtocolServer(server) {
  var srv = server && typeof server === 'object' ? server : {};
  var scheme = String(srv.scheme || 'smp').toLowerCase();
  if (scheme !== 'smp' && scheme !== 'ntf') fail('SMP_URI', 'protocol server scheme must be smp or ntf');
  var host = String(srv.host || '').trim();
  if (!/^[^:#,;\/\s]+$/.test(host)) fail('SMP_URI', 'protocol server host is invalid');
  var port = String(srv.port || '').trim();
  if (port) assertSafeInteger(port, 'server port', 1, 65535);
  return scheme + '://' + encodeBase64Url(srv.keyHash || new Uint8Array()) + '@' + host + (port ? ':' + port : '');
}

export function parseSmpQueueUri(value) {
  var text = String(value == null ? '' : value).trim();
  if (/[\x00-\x20\x7f]/.test(text)) fail('SMP_URI', 'SMP queue URI contains control or whitespace characters');
  var hashIndex = text.indexOf('#');
  if (hashIndex < 0 || hashIndex !== text.lastIndexOf('#')) fail('SMP_URI', 'SMP queue URI must contain one recipient key fragment');
  var beforeHash = text.slice(0, hashIndex);
  var recipientDhPublicKey = decodeBase64Url(text.slice(hashIndex + 1), 'recipient DH public key');
  if (!beforeHash.startsWith('smp://')) fail('SMP_URI', 'SMP queue URI must start with smp://');
  var slashIndex = beforeHash.indexOf('/', 'smp://'.length);
  if (slashIndex < 0 || slashIndex !== beforeHash.lastIndexOf('/')) fail('SMP_URI', 'SMP queue URI must contain exactly one queue path');
  var server = parseProtocolServer(beforeHash.slice(0, slashIndex));
  var queueId = decodeBase64Url(beforeHash.slice(slashIndex + 1), 'sender queue id');
  return { server, queueId, recipientDhPublicKey };
}

function parseNativeSmpQueueUri(value) {
  var text = String(value == null ? '' : value).trim();
  if (/[\x00-\x20\x7f]/.test(text)) fail('SMP_URI', 'native SMP queue URI contains control or whitespace characters');
  var hashIndex = text.indexOf('#');
  if (hashIndex < 0 || hashIndex !== text.lastIndexOf('#')) fail('SMP_URI', 'native SMP queue URI must contain one fragment');
  var beforeHash = text.slice(0, hashIndex);
  var fragment = text.slice(hashIndex + 1);
  if (!fragment.startsWith('/?')) fail('SMP_URI', 'native SMP queue URI fragment must start with /?');
  var params = new URLSearchParams(fragment.slice(2));
  var dh = params.get('dh') || '';
  if (!dh) fail('SMP_URI', 'native SMP queue URI is missing recipient DH key');
  if (!beforeHash.startsWith('smp://')) fail('SMP_URI', 'native SMP queue URI must start with smp://');
  var slashIndex = beforeHash.indexOf('/', 'smp://'.length);
  if (slashIndex < 0 || slashIndex !== beforeHash.lastIndexOf('/')) fail('SMP_URI', 'native SMP queue URI must contain exactly one queue path');
  var parsed = {
    server: parseProtocolServer(beforeHash.slice(0, slashIndex)),
    queueId: decodeBase64Url(beforeHash.slice(slashIndex + 1), 'sender queue id'),
    recipientDhPublicKey: decodeBase64Url(dh, 'recipient DH public key'),
    native: {
      version: params.get('v') || '',
      queueMode: params.get('q') || '',
      senderCanSecure: params.get('k') || '',
      onionHost: params.get('srv') || ''
    }
  };
  return parsed;
}

function parseNativeE2EParams(value) {
  var text = String(value == null ? '' : value).trim();
  if (!text) return null;
  if (/[\x00-\x20\x7f]/.test(text)) fail('SMP_URI', 'native E2E parameters contain control or whitespace characters');
  var params = new URLSearchParams(text);
  var x3dhText = params.get('x3dh') || '';
  if (!x3dhText) fail('SMP_URI', 'native E2E parameters are missing X3DH keys');
  var keys = x3dhText.split(',').map((keyText) => {
    var der = decodeBase64Url(keyText, 'native X3DH public key');
    var parsed = decodePublicKeyDer(der);
    if (parsed.algorithm !== 'X448') fail('SMP_URI', 'native X3DH public key must be X448');
    return parsed;
  });
  if (keys.length < 2 || keys.length > 4) fail('SMP_URI', 'native E2E parameters must contain two to four X3DH keys');
  return {
    version: params.get('v') || '',
    x3dhKeys: keys,
    raw: text
  };
}

export function parseSimplexConnectionLink(value) {
  var text = String(value == null ? '' : value).trim();
  if (/[\x00-\x20\x7f]/.test(text)) fail('SMP_URI', 'SimpleX connection link contains control or whitespace characters');
  if (text.startsWith('smp://')) {
    return {
      scheme: 'smp',
      type: 'queue',
      smpQueues: [parseSmpQueueUri(text)],
      e2e: '',
      browserProfile: true,
      nativeAgentProfile: false,
      queueUri: text
    };
  }
  var url;
  try {
    url = new URL(text);
  } catch (_error) {
    fail('SMP_URI', 'SimpleX connection link is invalid');
  }
  var simplexScheme = url.protocol === 'simplex:';
  var webScheme = url.protocol === 'https:' || url.protocol === 'http:';
  if (!simplexScheme && !webScheme) fail('SMP_URI', 'SimpleX connection link scheme is unsupported');
  var path = url.pathname.replace(/^\/+/, '');
  if (path !== 'invitation' && path !== 'contact') fail('SMP_URI', 'SimpleX connection link type is unsupported');
  var hash = String(url.hash || '');
  if (!hash.startsWith('#/?')) fail('SMP_URI', 'SimpleX connection link fragment must start with #/?');
  var params = new URLSearchParams(hash.slice(3));
  var smpParam = params.get('smp') || '';
  if (!smpParam) fail('SMP_URI', 'SimpleX connection link is missing SMP queue data');
  var queueTexts = smpParam.split(',');
  var queues = queueTexts.map((queueText) => {
    var q = String(queueText || '').trim();
    if (!q) fail('SMP_URI', 'SimpleX connection link contains an empty SMP queue');
    return q.includes('#/?') ? parseNativeSmpQueueUri(q) : parseSmpQueueUri(q);
  });
  var e2eText = params.get('e2e') || '';
  var nativeAgentProfile = !!e2eText || queues.some((queue) => !!(queue && queue.native));
  var nativeE2E = e2eText ? parseNativeE2EParams(e2eText) : null;
  return {
    scheme: simplexScheme ? 'simplex' : url.protocol.slice(0, -1),
    type: path,
    version: params.get('v') || '',
    smpQueues: queues,
    e2e: e2eText,
    nativeE2E,
    browserProfile: !nativeAgentProfile,
    nativeAgentProfile,
    queueUri: formatSmpQueueUri({
      server: queues[0].server,
      queueId: queues[0].queueId,
      recipientDhPublicKey: queues[0].recipientDhPublicKey
    })
  };
}

export function formatSmpQueueUri(queue) {
  var q = queue && typeof queue === 'object' ? queue : {};
  return formatProtocolServer(q.server) + '/' + encodeBase64Url(q.queueId || new Uint8Array()) + '#' + encodeBase64Url(q.recipientDhPublicKey || new Uint8Array());
}

const ED25519_SPKI_PREFIX = hexToBytes('302a300506032b6570032100');
const X25519_SPKI_PREFIX = hexToBytes('302a300506032b656e032100');
const X448_SPKI_PREFIX = hexToBytes('3042300506032b656f033900');
const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');
const X25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b656e04220420');
const X448_PKCS8_PREFIX = hexToBytes('3047020100300506032b656f043b0439');

export function hexToBytes(hex) {
  var text = String(hex == null ? '' : hex).trim();
  if (text.length % 2 || /[^0-9a-f]/i.test(text)) fail('SMP_HEX', 'hex string is invalid');
  var out = new Uint8Array(text.length / 2);
  for (var i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(toBytes(bytes, 'hex bytes'), (b) => b.toString(16).padStart(2, '0')).join('');
}

function normalizeRawKey(value, length, label) {
  var bytes = toBytes(value, label);
  if (bytes.length !== length) fail('SMP_KEY', label + ' must be ' + length + ' bytes');
  return bytes;
}

function normalizeEd25519SecretKey(value) {
  if (value && typeof value === 'object' && value.secretKey) return normalizeEd25519SecretKey(value.secretKey);
  var bytes = toBytes(value, 'Ed25519 secret key');
  if (bytes.length !== 32 && bytes.length !== 64) fail('SMP_KEY', 'Ed25519 secret key must be 32-byte seed or 64-byte expanded key');
  return bytes;
}

function normalizeEd25519PublicKey(value) {
  if (value && typeof value === 'object' && value.publicKey) return normalizeEd25519PublicKey(value.publicKey);
  if (value && typeof value === 'object' && value.rawPublicKey) return normalizeEd25519PublicKey(value.rawPublicKey);
  var bytes = toBytes(value, 'Ed25519 public key');
  if (bytes.length === ED25519_SPKI_PREFIX.length + 32 && hasPrefix(bytes, ED25519_SPKI_PREFIX)) {
    return bytes.slice(ED25519_SPKI_PREFIX.length);
  }
  return normalizeRawKey(bytes, 32, 'Ed25519 public key');
}

function normalizeX25519SecretKey(value) {
  if (value && typeof value === 'object' && value.secretKey) return normalizeX25519SecretKey(value.secretKey);
  return normalizeRawKey(value, 32, 'X25519 secret key');
}

function normalizeX25519PublicKey(value) {
  if (value && typeof value === 'object' && value.publicKey) return normalizeX25519PublicKey(value.publicKey);
  if (value && typeof value === 'object' && value.rawPublicKey) return normalizeX25519PublicKey(value.rawPublicKey);
  var bytes = toBytes(value, 'X25519 public key');
  if (bytes.length === X25519_SPKI_PREFIX.length + 32 && hasPrefix(bytes, X25519_SPKI_PREFIX)) {
    return bytes.slice(X25519_SPKI_PREFIX.length);
  }
  return normalizeRawKey(bytes, 32, 'X25519 public key');
}

function normalizeX448SecretKey(value) {
  if (value && typeof value === 'object' && value.secretKey) return normalizeX448SecretKey(value.secretKey);
  return normalizeRawKey(value, 56, 'X448 secret key');
}

function normalizeX448PublicKey(value) {
  if (value && typeof value === 'object' && value.publicKey) return normalizeX448PublicKey(value.publicKey);
  if (value && typeof value === 'object' && value.rawPublicKey) return normalizeX448PublicKey(value.rawPublicKey);
  var bytes = toBytes(value, 'X448 public key');
  if (bytes.length === X448_SPKI_PREFIX.length + 56 && hasPrefix(bytes, X448_SPKI_PREFIX)) {
    return bytes.slice(X448_SPKI_PREFIX.length);
  }
  return normalizeRawKey(bytes, 56, 'X448 public key');
}

function hasPrefix(bytes, prefix) {
  if (bytes.length < prefix.length) return false;
  for (var i = 0; i < prefix.length; i += 1) {
    if (bytes[i] !== prefix[i]) return false;
  }
  return true;
}

export function encodePublicKeyDer(algorithm, rawPublicKey) {
  var alg = String(algorithm || '').toUpperCase();
  if (alg === 'ED25519') return concatBytes(ED25519_SPKI_PREFIX, normalizeRawKey(rawPublicKey, 32, 'Ed25519 public key'));
  if (alg === 'X25519') return concatBytes(X25519_SPKI_PREFIX, normalizeRawKey(rawPublicKey, 32, 'X25519 public key'));
  if (alg === 'X448') return concatBytes(X448_SPKI_PREFIX, normalizeRawKey(rawPublicKey, 56, 'X448 public key'));
  fail('SMP_KEY', 'unsupported public key algorithm');
}

export function decodePublicKeyDer(der) {
  var bytes = toBytes(der, 'public key DER');
  if (bytes.length === ED25519_SPKI_PREFIX.length + 32 && hasPrefix(bytes, ED25519_SPKI_PREFIX)) {
    return { algorithm: 'Ed25519', rawPublicKey: bytes.slice(ED25519_SPKI_PREFIX.length) };
  }
  if (bytes.length === X25519_SPKI_PREFIX.length + 32 && hasPrefix(bytes, X25519_SPKI_PREFIX)) {
    return { algorithm: 'X25519', rawPublicKey: bytes.slice(X25519_SPKI_PREFIX.length) };
  }
  if (bytes.length === X448_SPKI_PREFIX.length + 56 && hasPrefix(bytes, X448_SPKI_PREFIX)) {
    return { algorithm: 'X448', rawPublicKey: bytes.slice(X448_SPKI_PREFIX.length) };
  }
  fail('SMP_KEY', 'unsupported public key DER');
}

export function encodePrivateKeyDer(algorithm, rawSecretKey) {
  var alg = String(algorithm || '').toUpperCase();
  if (alg === 'ED25519') return concatBytes(ED25519_PKCS8_PREFIX, normalizeRawKey(rawSecretKey, 32, 'Ed25519 secret seed'));
  if (alg === 'X25519') return concatBytes(X25519_PKCS8_PREFIX, normalizeRawKey(rawSecretKey, 32, 'X25519 secret key'));
  if (alg === 'X448') return concatBytes(X448_PKCS8_PREFIX, normalizeRawKey(rawSecretKey, 56, 'X448 secret key'));
  fail('SMP_KEY', 'unsupported private key algorithm');
}

export function generateEd25519KeyPair(seed) {
  var secretKey = seed == null ? randomBytes(32) : normalizeRawKey(seed, 32, 'Ed25519 seed');
  var publicKey = ed25519.getPublicKey(secretKey);
  return {
    algorithm: 'Ed25519',
    secretKey,
    publicKey,
    publicKeyDer: encodePublicKeyDer('Ed25519', publicKey),
    privateKeyDer: encodePrivateKeyDer('Ed25519', secretKey)
  };
}

export function generateX25519KeyPair(seed) {
  var secretKey = seed == null ? randomBytes(32) : normalizeRawKey(seed, 32, 'X25519 secret key');
  var publicKey = x25519.getPublicKey(secretKey);
  return {
    algorithm: 'X25519',
    secretKey,
    publicKey,
    publicKeyDer: encodePublicKeyDer('X25519', publicKey),
    privateKeyDer: encodePrivateKeyDer('X25519', secretKey)
  };
}

export function generateX448KeyPair(seed) {
  var secretKey = seed == null ? randomBytes(56) : normalizeRawKey(seed, 56, 'X448 secret key');
  var publicKey = x448.getPublicKey(secretKey);
  return {
    algorithm: 'X448',
    secretKey,
    publicKey,
    publicKeyDer: encodePublicKeyDer('X448', publicKey),
    privateKeyDer: encodePrivateKeyDer('X448', secretKey)
  };
}

export function ed25519Sign(privateKey, message) {
  return ed25519.sign(toBytes(message, 'message'), normalizeEd25519SecretKey(privateKey));
}

export function ed25519Verify(publicKey, message, signature) {
  return ed25519.verify(
    toBytes(signature, 'signature'),
    toBytes(message, 'message'),
    normalizeEd25519PublicKey(publicKey)
  );
}

export function x25519SharedSecret(privateKey, publicKey) {
  return x25519.getSharedSecret(normalizeX25519SecretKey(privateKey), normalizeX25519PublicKey(publicKey));
}

export function x448SharedSecret(privateKey, publicKey) {
  return x448.getSharedSecret(normalizeX448SecretKey(privateKey), normalizeX448PublicKey(publicKey));
}

export function sha256Hash(bytes) {
  return sha256(toBytes(bytes, 'hash input'));
}

export function randomBytes32() {
  return randomBytes(32);
}

export function randomNonce24() {
  return randomBytes(24);
}

export function padMessage(message, paddedLength) {
  return padBlock(message, paddedLength);
}

export function unpadMessage(message) {
  var input = toBytes(message, 'padded message');
  if (input.length < 2) fail('SMP_BAD_BLOCK', 'padded message is too short');
  var length = decodeWord16(input, 0);
  if (length > input.length - 2) fail('SMP_BAD_BLOCK', 'padded message length is invalid');
  for (var i = 2 + length; i < input.length; i += 1) {
    if (input[i] !== 0x23) fail('SMP_BAD_BLOCK', 'padded message contains non-padding bytes');
  }
  return input.slice(2, 2 + length);
}

export function encryptSecretBox(sharedSecret, nonce, plaintext, paddedLength) {
  var key = normalizeRawKey(sharedSecret, 32, 'XSalsa20-Poly1305 key');
  var nonceBytes = normalizeRawKey(nonce, 24, 'XSalsa20-Poly1305 nonce');
  var padded = padMessage(plaintext, paddedLength);
  return xsalsa20poly1305(key, nonceBytes).encrypt(padded);
}

export function decryptSecretBox(sharedSecret, nonce, packet) {
  var key = normalizeRawKey(sharedSecret, 32, 'XSalsa20-Poly1305 key');
  var nonceBytes = normalizeRawKey(nonce, 24, 'XSalsa20-Poly1305 nonce');
  try {
    return unpadMessage(xsalsa20poly1305(key, nonceBytes).decrypt(toBytes(packet, 'secretbox packet')));
  } catch (error) {
    if (error instanceof SimplexSmpProtocolError) throw error;
    fail('SMP_DECRYPT', 'XSalsa20-Poly1305 decryption failed');
  }
}

export function encryptAesGcm(key, iv, plaintext, paddedLength, aad = new Uint8Array()) {
  var keyBytes = normalizeRawKey(key, 32, 'AES-256-GCM key');
  var ivBytes = toBytes(iv, 'AES-GCM IV');
  if (ivBytes.length < 8) fail('SMP_KEY', 'AES-GCM IV must be at least 8 bytes');
  var packet = gcm(keyBytes, ivBytes, toBytes(aad, 'AES-GCM associated data')).encrypt(padMessage(plaintext, paddedLength));
  return {
    ciphertext: packet.slice(0, packet.length - 16),
    tag: packet.slice(packet.length - 16),
    packet
  };
}

export function decryptAesGcm(key, iv, ciphertext, tag, aad = new Uint8Array()) {
  var keyBytes = normalizeRawKey(key, 32, 'AES-256-GCM key');
  var ivBytes = toBytes(iv, 'AES-GCM IV');
  var packet = concatBytes(ciphertext, tag);
  try {
    return unpadMessage(gcm(keyBytes, ivBytes, toBytes(aad, 'AES-GCM associated data')).decrypt(packet));
  } catch (error) {
    if (error instanceof SimplexSmpProtocolError) throw error;
    fail('SMP_DECRYPT', 'AES-GCM decryption failed');
  }
}

export function browserTransportCapability() {
  // A normal browser WebSocket gives JavaScript an ordered byte stream, but it
  // does not expose raw TCP sockets, the TLS certificate bytes, or RFC5929
  // tls-unique channel binding.  A production direct-browser transport must
  // therefore use an SMP server/browser transport profile that provides an
  // auditable replacement for those checks, rather than silently downgrading.
  return {
    rawTcp: false,
    tlsCertificatePinningFromJs: false,
    tlsUniqueChannelBindingFromJs: false,
    websocketBinaryStream: typeof WebSocket !== 'undefined',
    requiresBrowserSmpServerProfile: true
  };
}

export default {
  SMP_BLOCK_SIZE,
  SMP_MAX_MESSAGE_LENGTH,
  SMP_MAX_RCV_MESSAGE_LENGTH,
  SMP_BROWSER_MIN_VERSION,
  SMP_BROWSER_MAX_VERSION,
  asciiBytes,
  asciiText,
  browserTransportCapability,
  bytesToHex,
  chooseCompatibleVersion,
  concatBytes,
  decodeBase64Url,
  decodePublicKeyDer,
  decodeTransportBlock,
  decryptAesGcm,
  decryptSecretBox,
  ed25519Sign,
  ed25519Verify,
  encodeBase64Url,
  encodeBrokerMessage,
  encodeClientHandshake,
  encodeCommand,
  encodePrivateKeyDer,
  encodePublicKeyDer,
  encodeServerHandshake,
  encodeSignedTransmission,
  encodeTransportBlock,
  encodeTransmission,
  encryptAesGcm,
  encryptSecretBox,
  equalBytes,
  formatProtocolServer,
  formatSmpQueueUri,
  generateEd25519KeyPair,
  generateX448KeyPair,
  generateX25519KeyPair,
  hexToBytes,
  padBlock,
  parseBrokerMessage,
  parseClientHandshake,
  parseCommand,
  parseProtocolServer,
  parseServerHandshake,
  parseSignedTransmission,
  parseSimplexConnectionLink,
  parseSmpQueueUri,
  randomBytes32,
  randomNonce24,
  sha256Hash,
  signTransmission,
  toBytes,
  unpadBlock,
  verifyTransmissionSignature,
  x25519SharedSecret,
  x448SharedSecret
};
