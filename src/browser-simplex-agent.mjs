// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser-native SimpleX agent helpers built on top of the SMP core.
//
// `browser-smp-core.mjs` knows how to encode bytes, commands, signatures, and
// transport blocks.  This module starts the next layer: the message envelopes
// and queue lifecycle records that a browser client needs before it can become
// a full SimpleX agent.
//
// This is still intentionally transport-agnostic.  Callers can feed the signed
// transmissions to a real browser SMP transport when that exists, or to test
// harnesses today.  No function here calls a plaintext compatibility API or sends
// plaintext through a web server.

import {
  SMP_E2E_ENC_CONFIRMATION_LENGTH,
  SMP_E2E_ENC_MESSAGE_LENGTH,
  SMP_MAX_RCV_MESSAGE_LENGTH,
  asciiBytes,
  asciiText,
  concatBytes,
  decodePublicKeyDer,
  decodeWord16,
  decodeWord64,
  encodeBrokerMessage,
  encodeBase64Url,
  encodeCommand,
  encodeLargeBytes,
  encodeMsgFlags,
  encodePublicKeyDer,
  encodeSmallBytes,
  encodeSignedTransmission,
  encodeTransportBlock,
  encodeWord16,
  encodeWord64,
  encryptSecretBox,
  equalBytes,
  formatProtocolServer,
  generateEd25519KeyPair,
  generateX448KeyPair,
  generateX25519KeyPair,
  parseSimplexConnectionLink,
  parseBrokerMessage,
  parseCommand,
  parseSignedTransmission,
  decryptSecretBox,
  toBytes,
  utf8Bytes,
  x25519SharedSecret,
  x448SharedSecret
} from './browser-smp-core.mjs';
import { randomBytes } from '@noble/ciphers/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import {
  createNativeSendingRatchet,
  encryptNativeRatchetMessage
} from './browser-simplex-native-ratchet.mjs';

export const SIMPLEX_AGENT_MESSAGE_VERSION = 1;
export const SIMPLEX_NATIVE_AGENT_MESSAGE_VERSION = 7;
export const SIMPLEX_NATIVE_E2E_VERSION = 2;
export const SIMPLEX_NATIVE_ENC_CONN_INFO_LENGTH = 14832;
export const SIMPLEX_EMPTY_PRIVATE_HEADER = '_';
export const SIMPLEX_CONFIRMATION_PRIVATE_HEADER = 'K';
export const SIMPLEX_NATIVE_X3DH_INFO = 'SimpleXX3DH';

class AgentProtocolError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SimplexBrowserAgentError';
    this.code = code;
  }
}

export { AgentProtocolError as SimplexBrowserAgentError };

function fail(code, message) {
  throw new AgentProtocolError(code, message);
}

function readSmall(reader, label) {
  var length = reader.takeByte(label + ' length');
  return reader.take(length, label);
}

class Reader {
  constructor(bytes, label) {
    this.bytes = toBytes(bytes, label || 'agent bytes');
    this.offset = 0;
  }

  takeByte(label) {
    if (this.offset >= this.bytes.length) fail('SIMPLEX_AGENT_TRUNCATED', label + ' is missing');
    return this.bytes[this.offset++];
  }

  take(length, label) {
    if (this.offset + length > this.bytes.length) fail('SIMPLEX_AGENT_TRUNCATED', label + ' is truncated');
    var out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  takeSmall(label) {
    return this.take(this.takeByte(label + ' length'), label);
  }

  takeLarge(label) {
    var length = decodeWord16(this.take(2, label + ' length'));
    return this.take(length, label);
  }

  tail() {
    return this.take(this.bytes.length - this.offset, 'tail');
  }

  done(label) {
    if (this.offset !== this.bytes.length) fail('SIMPLEX_AGENT_SYNTAX', label + ' has trailing bytes');
  }
}

function normalizeVersion(value) {
  var version = Number(value == null ? SIMPLEX_AGENT_MESSAGE_VERSION : value);
  if (!Number.isSafeInteger(version) || version < 1 || version > 0xffff) {
    fail('SIMPLEX_AGENT_VERSION', 'agent message version is invalid');
  }
  return version;
}

function normalizePrivateHeader(header) {
  var h = header && typeof header === 'object' ? header : { type: 'empty' };
  var type = String(h.type || 'empty').toLowerCase();
  if (type === 'empty') return { type: 'empty' };
  if (type === 'confirmation') {
    return { type: 'confirmation', senderPublicVerifyKey: toBytes(h.senderPublicVerifyKey, 'sender public verify key') };
  }
  fail('SIMPLEX_AGENT_HEADER', 'unsupported SimpleX private header');
}

function normalizePublicHeader(header) {
  var h = header && typeof header === 'object' ? header : {};
  return {
    version: normalizeVersion(h.version),
    e2ePubDhKey: h.e2ePubDhKey ? toBytes(h.e2ePubDhKey, 'E2E public DH key') : null
  };
}

function normalizeX448KeyPair(value, label) {
  var key = value && typeof value === 'object' ? value : {};
  var publicKey = key.publicKey || key.rawPublicKey || null;
  if (!publicKey && key.publicKeyDer) {
    var decodedPublic = decodePublicKeyDer(key.publicKeyDer);
    if (decodedPublic.algorithm !== 'X448') fail('SIMPLEX_AGENT_X3DH', label + ' public key must be X448');
    publicKey = decodedPublic.rawPublicKey;
  }
  var secretKey = key.secretKey || key.privateKey || null;
  if (!secretKey) fail('SIMPLEX_AGENT_X3DH', label + ' secret key is missing');
  var secret = toBytes(secretKey, label + ' secret key');
  var pub = toBytes(publicKey || generateX448KeyPair(secret).publicKey, label + ' public key');
  if (secret.length !== 56 || pub.length !== 56) fail('SIMPLEX_AGENT_X3DH', label + ' keys must be X448 keys');
  return { secretKey: secret, publicKey: pub };
}

function normalizeX448PublicKey(value, label) {
  if (value && typeof value === 'object') {
    if (value.algorithm && value.algorithm !== 'X448') fail('SIMPLEX_AGENT_X3DH', label + ' must be X448');
    if (value.rawPublicKey) return normalizeX448PublicKey(value.rawPublicKey, label);
    if (value.publicKey) return normalizeX448PublicKey(value.publicKey, label);
    if (value.publicKeyDer) return normalizeX448PublicKey(decodePublicKeyDer(value.publicKeyDer), label);
  }
  var key = toBytes(value, label);
  if (key.length !== 56) {
    try {
      return normalizeX448PublicKey(decodePublicKeyDer(key), label);
    } catch (_error) {
      // Fall through to the stable X448 length error below.
    }
  }
  if (key.length !== 56) fail('SIMPLEX_AGENT_X3DH', label + ' must be a 56-byte X448 public key');
  return key;
}

function hkdf3(salt, ikm, info) {
  var out = hkdf(sha512, salt, ikm, utf8Bytes(info), 96);
  return {
    ratchetKey: out.slice(0, 32),
    sendHeaderKey: out.slice(32, 64),
    receiveNextHeaderKey: out.slice(64, 96)
  };
}

function simplexX3dh(firstPublicPair, dh1, dh2, dh3, kemSecret) {
  var salt = new Uint8Array(64);
  var ikm = concatBytes(dh1, dh2, dh3, kemSecret || new Uint8Array());
  return {
    associatedData: concatBytes(firstPublicPair[0], firstPublicPair[1]),
    ...hkdf3(salt, ikm, SIMPLEX_NATIVE_X3DH_INFO)
  };
}

export function deriveNativeX3dhSender(options = {}) {
  // Upstream SimpleX uses this path for the peer joining an invitation:
  // DH(rk1, spk2) || DH(rk2, spk1) || DH(rk2, spk2), HKDF-SHA512,
  // where `rk*` are recipient invitation keys and `spk*` are sender keys.
  var senderKey1 = normalizeX448KeyPair(options.senderKey1 || options.spk1, 'sender X3DH key 1');
  var senderKey2 = normalizeX448KeyPair(options.senderKey2 || options.spk2, 'sender X3DH key 2');
  var recipientKey1 = normalizeX448PublicKey(options.recipientKey1 || options.rk1, 'recipient X3DH key 1');
  var recipientKey2 = normalizeX448PublicKey(options.recipientKey2 || options.rk2, 'recipient X3DH key 2');
  return simplexX3dh(
    [senderKey1.publicKey, recipientKey1],
    x448SharedSecret(senderKey2.secretKey, recipientKey1),
    x448SharedSecret(senderKey1.secretKey, recipientKey2),
    x448SharedSecret(senderKey2.secretKey, recipientKey2),
    options.kemSecret
  );
}

export function deriveNativeX3dhReceiver(options = {}) {
  // Upstream SimpleX uses this path for the invitation creator after receiving
  // the joiner's reply: the same three DHs as the sender, evaluated from the
  // opposite private keys.
  var recipientKey1 = normalizeX448KeyPair(options.recipientKey1 || options.rpk1, 'recipient X3DH key 1');
  var recipientKey2 = normalizeX448KeyPair(options.recipientKey2 || options.rpk2, 'recipient X3DH key 2');
  var senderKey1 = normalizeX448PublicKey(options.senderKey1 || options.sk1, 'sender X3DH key 1');
  var senderKey2 = normalizeX448PublicKey(options.senderKey2 || options.sk2, 'sender X3DH key 2');
  return simplexX3dh(
    [senderKey1, recipientKey1.publicKey],
    x448SharedSecret(recipientKey1.secretKey, senderKey2),
    x448SharedSecret(recipientKey2.secretKey, senderKey1),
    x448SharedSecret(recipientKey2.secretKey, senderKey2),
    options.kemSecret
  );
}

export function encodePublicHeader(header = {}) {
  // Upstream `PubHeader` is `(Version, Maybe PublicKey)`: two bytes for the
  // version, then ASCII `0` for no key or ASCII `1` plus a length-prefixed DER
  // key when the sender includes an E2E public DH key.
  var h = normalizePublicHeader(header);
  if (!h.e2ePubDhKey) return concatBytes(encodeWord16(h.version), asciiBytes('0'));
  return concatBytes(encodeWord16(h.version), asciiBytes('1'), new Uint8Array([h.e2ePubDhKey.length]), h.e2ePubDhKey);
}

export function parsePublicHeader(bytes) {
  var reader = new Reader(bytes, 'public header');
  var version = decodeWord16(reader.take(2, 'agent message version'));
  var tag = reader.takeByte('public header key tag');
  if (tag === 0x30) {
    return { header: { version, e2ePubDhKey: null }, rest: reader.tail() };
  }
  if (tag === 0x31) {
    return { header: { version, e2ePubDhKey: readSmall(reader, 'E2E public DH key') }, rest: reader.tail() };
  }
  fail('SIMPLEX_AGENT_HEADER', 'public header key tag must be 0 or 1');
}

export function encodePrivateHeader(header = {}) {
  // Upstream Haskell uses `_` for the empty private header and `K<key>` for the
  // confirmation header that carries the sender's SMP signing public key.
  var h = normalizePrivateHeader(header);
  if (h.type === 'empty') return asciiBytes(SIMPLEX_EMPTY_PRIVATE_HEADER);
  return concatBytes(asciiBytes(SIMPLEX_CONFIRMATION_PRIVATE_HEADER), new Uint8Array([h.senderPublicVerifyKey.length]), h.senderPublicVerifyKey);
}

export function parsePrivateHeader(bytes) {
  var reader = new Reader(bytes, 'private header');
  var tag = reader.takeByte('private header tag');
  if (tag === 0x5f || tag === 0x20) {
    return { header: { type: 'empty' }, body: reader.tail() };
  }
  if (tag === 0x4b) {
    return {
      header: { type: 'confirmation', senderPublicVerifyKey: readSmall(reader, 'sender public verify key') },
      body: reader.tail()
    };
  }
  fail('SIMPLEX_AGENT_HEADER', 'private header tag is unsupported');
}

function encodeMaybeLargeBytes(value) {
  if (value == null) return asciiBytes('0');
  return concatBytes(asciiBytes('1'), encodeLargeBytes(value));
}

function parseMaybeLargeBytes(reader, label) {
  var tag = reader.takeByte(label + ' tag');
  if (tag === 0x30) return null;
  if (tag === 0x31) return reader.takeLarge(label);
  fail('SIMPLEX_AGENT_ENVELOPE', label + ' tag must be 0 or 1');
}

export function encodeNativeAgentEnvelope(envelope = {}) {
  var version = normalizeVersion(envelope.agentVersion || envelope.version || SIMPLEX_AGENT_MESSAGE_VERSION);
  var type = String(envelope.type || '').toLowerCase();
  if (type === 'confirmation') {
    return concatBytes(
      encodeWord16(version),
      asciiBytes('C'),
      encodeMaybeLargeBytes(envelope.e2eEncryption || envelope.e2eEncryptionBytes || null),
      toBytes(envelope.encConnInfo || envelope.body || new Uint8Array(), 'encrypted connection info')
    );
  }
  if (type === 'message') {
    return concatBytes(
      encodeWord16(version),
      asciiBytes('M'),
      toBytes(envelope.encAgentMessage || envelope.body || new Uint8Array(), 'encrypted agent message')
    );
  }
  if (type === 'invitation') {
    return concatBytes(
      encodeWord16(version),
      asciiBytes('I'),
      encodeLargeBytes(envelope.connReq || envelope.connectionRequest || new Uint8Array()),
      toBytes(envelope.connInfo || new Uint8Array(), 'invitation connection info')
    );
  }
  if (type === 'ratchet-key') {
    return concatBytes(
      encodeWord16(version),
      asciiBytes('R'),
      encodeLargeBytes(envelope.e2eEncryption || envelope.e2eEncryptionBytes || new Uint8Array()),
      toBytes(envelope.info || new Uint8Array(), 'ratchet key info')
    );
  }
  fail('SIMPLEX_AGENT_ENVELOPE', 'native agent envelope type is unsupported');
}

export function parseNativeAgentEnvelope(bytes) {
  var reader = new Reader(bytes, 'native agent envelope');
  var agentVersion = decodeWord16(reader.take(2, 'agent version'));
  var tag = reader.takeByte('native agent envelope tag');
  if (tag === 0x43) {
    return {
      type: 'confirmation',
      agentVersion,
      e2eEncryption: parseMaybeLargeBytes(reader, 'E2E encryption'),
      encConnInfo: reader.tail()
    };
  }
  if (tag === 0x4d) return { type: 'message', agentVersion, encAgentMessage: reader.tail() };
  if (tag === 0x49) {
    return { type: 'invitation', agentVersion, connReq: reader.takeLarge('connection request'), connInfo: reader.tail() };
  }
  if (tag === 0x52) {
    return { type: 'ratchet-key', agentVersion, e2eEncryption: reader.takeLarge('E2E encryption'), info: reader.tail() };
  }
  fail('SIMPLEX_AGENT_ENVELOPE', 'native agent envelope tag is unsupported');
}

function normalizeAgentMsgId(value, label) {
  var n = typeof value === 'bigint' ? value : BigInt(Number(value || 0));
  if (n < 0n || n > 0x7fffffffffffffffn) fail('SIMPLEX_AGENT_MESSAGE_ID', label + ' is invalid');
  return n;
}

function normalizeX448PublicDer(value, label) {
  if (value && typeof value === 'object') {
    if (value.publicKeyDer) return normalizeX448PublicDer(value.publicKeyDer, label);
    if (value.publicKey || value.rawPublicKey) {
      var key = toBytes(value.publicKey || value.rawPublicKey, label + ' public key');
      if (key.length !== 56) fail('SIMPLEX_AGENT_X3DH', label + ' public key must be X448');
      return encodePublicKeyDer('X448', key);
    }
  }
  var der = toBytes(value, label + ' public key DER');
  var decoded = decodePublicKeyDer(der);
  if (decoded.algorithm !== 'X448') fail('SIMPLEX_AGENT_X3DH', label + ' public key must be X448');
  return der;
}

function encodeProtocolServerBinary(server = {}) {
  var host = String(server.host || '').trim();
  if (!host || /[:,;\/\s]/.test(host)) fail('SIMPLEX_AGENT_QUEUE', 'protocol server host is invalid');
  return concatBytes(
    new Uint8Array([1]),
    encodeSmallBytes(asciiBytes(host)),
    encodeSmallBytes(asciiBytes(server.port || '')),
    encodeSmallBytes(server.keyHash || new Uint8Array())
  );
}

function encodeQueueMode(value) {
  var mode = String(value || 'm').toLowerCase();
  if (mode === 'm' || mode === 'messaging') return asciiBytes('M');
  if (mode === 'c' || mode === 'contact') return asciiBytes('C');
  fail('SIMPLEX_AGENT_QUEUE', 'native queue mode is unsupported');
}

function normalizeReplyQueue(queue = {}) {
  if (!queue.server) fail('SIMPLEX_AGENT_QUEUE', 'native reply queue requires a server');
  var senderId = queue.senderId || queue.sndId || queue.queueId;
  var dhPublicKey = queue.dhPublicKey || queue.recipientDhPublicKey ||
    (queue.rcvDhKey && queue.rcvDhKey.publicKeyDer);
  return {
    clientVersion: Number(queue.clientVersion || 4),
    server: queue.server,
    senderId: toBytes(senderId, 'reply queue sender id'),
    dhPublicKey: toBytes(dhPublicKey, 'reply queue DH public key'),
    queueMode: queue.queueMode || 'm'
  };
}

export function encodeNativeSmpQueueInfo(queue = {}) {
  var q = normalizeReplyQueue(queue);
  if (q.clientVersion < 4) fail('SIMPLEX_AGENT_QUEUE', 'native reply queue must use SMP client version 4 or newer');
  return concatBytes(
    encodeWord16(q.clientVersion),
    encodeProtocolServerBinary(q.server),
    encodeSmallBytes(q.senderId),
    encodeSmallBytes(q.dhPublicKey),
    encodeQueueMode(q.queueMode)
  );
}

export function encodeNativeAgentConnInfo(message = {}) {
  var type = String(message.type || (message.replyQueues ? 'reply' : 'info')).toLowerCase();
  var connInfo = toBytes(message.connInfo || new Uint8Array(), 'native connection info');
  if (type === 'info') return concatBytes(asciiBytes('I'), connInfo);
  if (type === 'reply' || type === 'conn-info-reply') {
    var queues = Array.isArray(message.replyQueues) ? message.replyQueues : [message.replyQueue].filter(Boolean);
    if (!queues.length || queues.length > 255) fail('SIMPLEX_AGENT_QUEUE', 'native connection reply requires one to 255 reply queues');
    return concatBytes(
      asciiBytes('D'),
      new Uint8Array([queues.length]),
      ...queues.map(encodeNativeSmpQueueInfo),
      connInfo
    );
  }
  fail('SIMPLEX_AGENT_MESSAGE', 'native connection info message type is unsupported');
}

export function parseNativeAgentConnInfo(bytes) {
  var reader = new Reader(bytes, 'native connection info message');
  var tag = reader.takeByte('native connection info tag');
  if (tag === 0x49) return { type: 'info', connInfo: reader.tail() };
  if (tag !== 0x44) fail('SIMPLEX_AGENT_MESSAGE', 'native connection info tag is unsupported');
  var count = reader.takeByte('native reply queue count');
  if (!count) fail('SIMPLEX_AGENT_QUEUE', 'native connection reply queue list is empty');
  var queues = [];
  for (var i = 0; i < count; i += 1) {
    var clientVersion = decodeWord16(reader.take(2, 'reply queue client version'));
    var hostCount = reader.takeByte('reply queue host count');
    if (!hostCount) fail('SIMPLEX_AGENT_QUEUE', 'reply queue host list is empty');
    var hosts = [];
    for (var h = 0; h < hostCount; h += 1) hosts.push(asciiText(reader.takeSmall('reply queue host')));
    queues.push({
      clientVersion,
      server: {
        scheme: 'smp',
        host: hosts[0],
        hosts,
        port: asciiText(reader.takeSmall('reply queue port')),
        keyHash: reader.takeSmall('reply queue server identity hash')
      },
      senderId: reader.takeSmall('reply queue sender id'),
      dhPublicKey: reader.takeSmall('reply queue DH public key'),
      queueMode: asciiText(reader.take(1, 'reply queue mode'))
    });
  }
  return { type: 'reply', replyQueues: queues, connInfo: reader.tail() };
}

export function encodeNativeE2ERatchetParams(params = {}) {
  var version = normalizeVersion(params.version || 2);
  if (version >= 3 && params.kem) fail('SIMPLEX_AGENT_X3DH', 'native PQ ratchet params are not implemented yet');
  return concatBytes(
    encodeWord16(version),
    encodeSmallBytes(normalizeX448PublicDer(params.key1 || params.x3dhKey1 || params.publicKey1, 'native E2E key 1')),
    encodeSmallBytes(normalizeX448PublicDer(params.key2 || params.x3dhKey2 || params.publicKey2, 'native E2E key 2'))
  );
}

export function parseNativeE2ERatchetParams(bytes) {
  var reader = new Reader(bytes, 'native E2E ratchet params');
  var version = decodeWord16(reader.take(2, 'native E2E version'));
  var key1 = decodePublicKeyDer(reader.takeSmall('native E2E key 1'));
  var key2 = decodePublicKeyDer(reader.takeSmall('native E2E key 2'));
  if (key1.algorithm !== 'X448' || key2.algorithm !== 'X448') {
    fail('SIMPLEX_AGENT_X3DH', 'native E2E ratchet keys must be X448');
  }
  reader.done('native E2E ratchet params');
  return { version, key1, key2 };
}

export function encodeNativeAgentMessage(message = {}) {
  var type = String(message.type || '').toLowerCase();
  if (type === 'hello') return asciiBytes('H');
  if (type === 'message') return concatBytes(asciiBytes('M'), toBytes(message.body || new Uint8Array(), 'agent message body'));
  if (type === 'receipt') {
    var receipts = Array.isArray(message.receipts) ? message.receipts : [];
    if (!receipts.length || receipts.length > 255) fail('SIMPLEX_AGENT_RECEIPT', 'native receipt list must contain one to 255 receipts');
    return concatBytes(
      asciiBytes('V'),
      new Uint8Array([receipts.length]),
      ...receipts.map((receipt) => concatBytes(
        encodeWord64(normalizeAgentMsgId(receipt.agentMsgId || receipt.id, 'receipt message id')),
        encodeSmallBytes(receipt.msgHash || receipt.hash || new Uint8Array()),
        encodeLargeBytes(receipt.rcptInfo || receipt.info || new Uint8Array())
      ))
    );
  }
  fail('SIMPLEX_AGENT_MESSAGE', 'native agent message type is unsupported');
}

export function parseNativeAgentMessage(bytes) {
  var reader = new Reader(bytes, 'native agent message');
  var tag = reader.takeByte('native agent message tag');
  if (tag === 0x48) {
    reader.done('HELLO');
    return { type: 'hello' };
  }
  if (tag === 0x4d) return { type: 'message', body: reader.tail() };
  if (tag === 0x56) {
    var count = reader.takeByte('receipt count');
    if (!count) fail('SIMPLEX_AGENT_RECEIPT', 'native receipt list must be non-empty');
    var receipts = [];
    for (var i = 0; i < count; i += 1) {
      receipts.push({
        agentMsgId: decodeWord64(reader.take(8, 'receipt message id')),
        msgHash: reader.takeSmall('receipt message hash'),
        rcptInfo: reader.takeLarge('receipt info')
      });
    }
    reader.done('receipt list');
    return { type: 'receipt', receipts };
  }
  fail('SIMPLEX_AGENT_MESSAGE', 'native agent message tag is unsupported');
}

export function encodeClientMessage(message = {}) {
  return concatBytes(
    encodePrivateHeader(message.privateHeader),
    toBytes(message.body || new Uint8Array(), 'client message body')
  );
}

export function parseClientMessage(bytes) {
  return parsePrivateHeader(bytes);
}

function defaultClientPadding(publicHeader) {
  return publicHeader && publicHeader.e2ePubDhKey
    ? SMP_E2E_ENC_CONFIRMATION_LENGTH
    : SMP_E2E_ENC_MESSAGE_LENGTH;
}

export function encodeClientMessageEnvelope(envelope = {}) {
  var publicHeader = normalizePublicHeader(envelope.publicHeader);
  return concatBytes(
    encodePublicHeader(publicHeader),
    toBytes(envelope.nonce, 'client message nonce'),
    toBytes(envelope.encryptedBody, 'encrypted client message body')
  );
}

export function parseClientMessageEnvelope(bytes) {
  var parsedHeader = parsePublicHeader(bytes);
  var reader = new Reader(parsedHeader.rest, 'client message envelope');
  return {
    publicHeader: parsedHeader.header,
    nonce: reader.take(24, 'client message nonce'),
    encryptedBody: reader.tail()
  };
}

export function encryptClientMessage(options = {}) {
  var publicHeader = normalizePublicHeader(options.publicHeader);
  var nonce = toBytes(options.nonce, 'client message nonce');
  if (nonce.length !== 24) fail('SIMPLEX_AGENT_NONCE', 'client message nonce must be 24 bytes');
  var clientMessage = encodeClientMessage({
    privateHeader: options.privateHeader,
    body: options.body || new Uint8Array()
  });
  var paddedLength = options.paddedLength || defaultClientPadding(publicHeader);
  var encryptedBody = encryptSecretBox(options.sharedSecret, nonce, clientMessage, paddedLength);
  return encodeClientMessageEnvelope({ publicHeader, nonce, encryptedBody });
}

export function decryptClientMessageEnvelope(options = {}) {
  var envelope = parseClientMessageEnvelope(options.envelope);
  var decrypted = decryptSecretBox(options.sharedSecret, envelope.nonce, envelope.encryptedBody);
  var clientMessage = parseClientMessage(decrypted);
  return {
    publicHeader: envelope.publicHeader,
    privateHeader: clientMessage.header,
    body: clientMessage.body
  };
}

export function messageIdNonce(msgId) {
  // SimpleX uses `cbNonce`: truncate IDs longer than 24 bytes, or right-pad
  // shorter IDs with zeroes until the XSalsa20 nonce is 24 bytes.
  var id = toBytes(msgId, 'message id');
  if (id.length >= 24) return id.slice(0, 24);
  var nonce = new Uint8Array(24);
  nonce.set(id, 0);
  return nonce;
}

export function encodeRcvMessageBody(message = {}) {
  return concatBytes(
    encodeWord64(message.timestamp || 0),
    encodeMsgFlags(message.flags || {}),
    asciiBytes(' '),
    toBytes(message.body || new Uint8Array(), 'received message body')
  );
}

export function parseRcvMessageBody(bytes) {
  var reader = new Reader(bytes, 'received message body');
  var timestamp = decodeWord64(reader.take(8, 'message timestamp'));
  var flag = reader.takeByte('message notification flag');
  if (flag !== 0x54 && flag !== 0x46) fail('SIMPLEX_AGENT_SYNTAX', 'message notification flag must be T or F');
  while (reader.offset < reader.bytes.length) {
    if (reader.takeByte('message flag separator') === 0x20) {
      return {
        timestamp,
        flags: { notification: flag === 0x54 },
        body: reader.tail()
      };
    }
  }
  fail('SIMPLEX_AGENT_SYNTAX', 'received message body is missing the flag separator');
}

export function encryptRcvMessageBody(options = {}) {
  var body = encodeRcvMessageBody(options);
  return encryptSecretBox(
    options.serverDhSecret,
    messageIdNonce(options.msgId),
    body,
    SMP_MAX_RCV_MESSAGE_LENGTH + 2
  );
}

export function decryptRcvMessageBody(options = {}) {
  return parseRcvMessageBody(decryptSecretBox(
    options.serverDhSecret,
    messageIdNonce(options.msgId),
    options.encryptedBody
  ));
}

export function prepareNewQueueRequest(options = {}) {
  // `NEW` is signed by the recipient key, but it has an empty queue ID because
  // the queue IDs do not exist until the server answers with `IDS`.
  var rcvSignKey = generateEd25519KeyPair(options.rcvSignSeed);
  var rcvDhKey = generateX25519KeyPair(options.rcvDhSeed);
  var command = {
    type: 'NEW',
    rcvPublicVerifyKey: rcvSignKey.publicKeyDer,
    rcvPublicDhKey: rcvDhKey.publicKeyDer
  };
  var transmission = encodeSignedTransmission(options.version || 4, options.sessionId || new Uint8Array(), {
    privateKey: rcvSignKey.secretKey,
    corrId: options.corrId || new Uint8Array(),
    queueId: new Uint8Array(),
    command
  });
  return {
    server: options.server || null,
    rcvSignKey,
    rcvDhKey,
    command,
    transmission,
    transportBlock: options.transportBlock === false
      ? null
      : encodeTransportBlock(options.version || 4, [transmission])
  };
}

function normalizeBrokerMessage(value, version) {
  if (value && typeof value === 'object' && value.type) return value;
  return parseBrokerMessage(version || 4, toBytes(value, 'broker message bytes'));
}

export function completeNewQueueRequest(pending, brokerMessage, options = {}) {
  var request = pending && typeof pending === 'object' ? pending : {};
  var ids = normalizeBrokerMessage(brokerMessage, options.version || 4);
  if (ids.type !== 'IDS') fail('SIMPLEX_AGENT_IDS', 'new queue request must complete with IDS');
  var serverDhPublic = decodePublicKeyDer(ids.rcvPublicDhKey);
  if (serverDhPublic.algorithm !== 'X25519') fail('SIMPLEX_AGENT_IDS', 'IDS server DH key must be X25519');
  return {
    server: request.server || options.server || null,
    rcvId: ids.rcvId,
    sndId: ids.sndId,
    rcvSignKey: request.rcvSignKey,
    rcvDhKey: request.rcvDhKey,
    serverDhPublicKeyDer: ids.rcvPublicDhKey,
    serverDhPublicKey: serverDhPublic.rawPublicKey,
    serverDhSecret: x25519SharedSecret(request.rcvDhKey.secretKey, serverDhPublic.rawPublicKey)
  };
}

export function prepareRecipientCommand(queue, options = {}) {
  var q = queue && typeof queue === 'object' ? queue : {};
  if (!q.rcvSignKey || !q.rcvId) fail('SIMPLEX_AGENT_QUEUE', 'recipient queue state is incomplete');
  var command = options.command || { type: options.type || 'SUB' };
  return encodeSignedTransmission(options.version || 4, options.sessionId || new Uint8Array(), {
    privateKey: q.rcvSignKey.secretKey,
    corrId: options.corrId || new Uint8Array(),
    queueId: q.rcvId,
    command
  });
}

export function prepareInitialSenderMessage(options = {}) {
  // The initial sender message is unsigned at SMP level until the recipient
  // secures the queue with `KEY`.  The encrypted client message still carries
  // the sender's public signing key in the confirmation private header.
  var senderSignKey = options.senderSignKey || generateEd25519KeyPair(options.senderSignSeed);
  var privateHeader = options.privateHeader || {
    type: 'confirmation',
    senderPublicVerifyKey: senderSignKey.publicKeyDer
  };
  var envelope = encryptClientMessage({
    sharedSecret: options.e2eSharedSecret,
    nonce: options.nonce || randomBytes(24),
    publicHeader: {
      version: options.clientVersion || options.smpClientVersion || options.version || SIMPLEX_AGENT_MESSAGE_VERSION,
      e2ePubDhKey: options.senderE2ePubDhKey || null
    },
    privateHeader,
    body: options.body || new Uint8Array()
  });
  var command = {
    type: 'SEND',
    flags: options.flags || { notification: false },
    body: envelope
  };
  var transmission = encodeSignedTransmission(options.version || 4, options.sessionId || new Uint8Array(), {
    signature: new Uint8Array(),
    corrId: options.corrId || new Uint8Array(),
    queueId: options.senderQueueId,
    command
  });
  return { senderSignKey, envelope, command, transmission };
}

function nativeInvitationUriFromQueue(queue, x3dhKey1, x3dhKey2, options = {}) {
  var q = queue && typeof queue === 'object' ? queue : {};
  if (!q.server) fail('SIMPLEX_AGENT_QUEUE', 'native invitation queue requires a server');
  var senderId = q.sndId || q.senderId || q.queueId;
  var dhPublicKey = q.recipientDhPublicKey || (q.rcvDhKey && q.rcvDhKey.publicKeyDer);
  var queueUri = formatProtocolServer(q.server) + '/' + encodeBase64Url(senderId || new Uint8Array()) +
    '#/?v=1-4&dh=' + encodeURIComponent(encodeBase64Url(dhPublicKey || new Uint8Array())) +
    '&q=' + encodeURIComponent(String(options.queueMode || q.queueMode || 'm').toLowerCase().slice(0, 1) || 'm');
  var e2e = 'v=2-3&x3dh=' + [
    encodeBase64Url(x3dhKey1.publicKeyDer || encodePublicKeyDer('X448', x3dhKey1.publicKey)),
    encodeBase64Url(x3dhKey2.publicKeyDer || encodePublicKeyDer('X448', x3dhKey2.publicKey))
  ].join(',');
  return 'simplex:/invitation#/?v=2-7&smp=' + encodeURIComponent(queueUri) + '&e2e=' + encodeURIComponent(e2e);
}

function nativeProfileConnInfo(profile = {}) {
  // The SimpleX Chat layer expects agent connection info to be a serialized
  // ChatMessage. For a basic profile exchange that is the `x.info` event.
  return utf8Bytes(JSON.stringify({
    event: 'x.info',
    params: { profile: profile && typeof profile === 'object' ? profile : {} }
  }));
}

export function prepareNativeContactRequest(options = {}) {
  var link = options.link && typeof options.link === 'object'
    ? options.link
    : parseSimplexConnectionLink(options.invitationUri || options.invitation_uri || options.contactLink || options.contact_link);
  if (!link.nativeAgentProfile || link.type !== 'contact') {
    fail('SIMPLEX_AGENT_NATIVE_CONTACT', 'native contact request requires a native SimpleX contact link');
  }
  var contactQueue = link.smpQueues[0];
  if (!contactQueue) fail('SIMPLEX_AGENT_NATIVE_CONTACT', 'native contact link does not contain an SMP queue');
  var recipientQueueDh = decodePublicKeyDer(contactQueue.recipientDhPublicKey);
  if (recipientQueueDh.algorithm !== 'X25519') fail('SIMPLEX_AGENT_NATIVE_CONTACT', 'native contact queue DH key must be X25519');
  var replyQueue = options.replyQueue;
  if (!replyQueue) fail('SIMPLEX_AGENT_NATIVE_CONTACT', 'native contact request requires a reply queue');

  var senderQueueDh = options.senderQueueDhKey || options.ownDhKey || generateX25519KeyPair(options.ownDhSeed);
  var recipientX3dhKey1 = options.recipientX3dhKey1 || generateX448KeyPair(options.recipientX3dhSeed1);
  var recipientX3dhKey2 = options.recipientX3dhKey2 || generateX448KeyPair(options.recipientX3dhSeed2);
  var connReq = nativeInvitationUriFromQueue(replyQueue, recipientX3dhKey1, recipientX3dhKey2, options);
  var connInfo = options.connInfo == null
    ? nativeProfileConnInfo(options.profile || {})
    : toBytes(options.connInfo, 'native contact info');
  var body = encodeNativeAgentEnvelope({
    type: 'invitation',
    version: options.nativeAgentVersion || SIMPLEX_NATIVE_AGENT_MESSAGE_VERSION,
    connReq: utf8Bytes(connReq),
    connInfo
  });
  var shared = x25519SharedSecret(senderQueueDh.secretKey, recipientQueueDh.rawPublicKey);
  var prepared = prepareInitialSenderMessage({
    version: options.version || 4,
    sessionId: options.sessionId || new Uint8Array(),
    corrId: options.corrId || new Uint8Array(),
    senderQueueId: contactQueue.queueId,
    senderSignKey: options.senderSignKey,
    senderSignSeed: options.senderSignSeed,
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderQueueDh.publicKeyDer,
    privateHeader: { type: 'empty' },
    nonce: options.nonce,
    body,
    flags: options.flags
  });
  return {
    ...prepared,
    link,
    contactQueue,
    replyQueue,
    connReq,
    perQueueSharedSecret: shared,
    senderQueueDh,
    recipientX3dhKey1,
    recipientX3dhKey2,
    agentEnvelope: body
  };
}

export function prepareNativeInvitationJoin(options = {}) {
  var link = options.link && typeof options.link === 'object'
    ? options.link
    : parseSimplexConnectionLink(options.invitationUri || options.invitation_uri || options.contactLink || options.contact_link);
  if (!link.nativeAgentProfile || !link.nativeE2E) {
    fail('SIMPLEX_AGENT_NATIVE_JOIN', 'native invitation join requires a native SimpleX invitation link');
  }
  var invitationQueue = link.smpQueues[0];
  if (!invitationQueue) fail('SIMPLEX_AGENT_NATIVE_JOIN', 'native invitation does not contain an SMP queue');
  var recipientQueueDh = decodePublicKeyDer(invitationQueue.recipientDhPublicKey);
  if (recipientQueueDh.algorithm !== 'X25519') fail('SIMPLEX_AGENT_NATIVE_JOIN', 'native invitation queue DH key must be X25519');
  var recipientE2eKey1 = link.nativeE2E.x3dhKeys[0];
  var recipientE2eKey2 = link.nativeE2E.x3dhKeys[1];
  if (!recipientE2eKey1 || !recipientE2eKey2) fail('SIMPLEX_AGENT_NATIVE_JOIN', 'native invitation is missing X3DH keys');

  var senderQueueDh = options.senderQueueDhKey || options.ownDhKey || generateX25519KeyPair(options.ownDhSeed);
  var senderX3dhKey1 = options.senderX3dhKey1 || generateX448KeyPair(options.senderX3dhSeed1);
  var senderX3dhKey2 = options.senderX3dhKey2 || generateX448KeyPair(options.senderX3dhSeed2);
  var senderRatchetDh = options.senderRatchetDhKey || generateX448KeyPair(options.senderRatchetSeed);
  var init = deriveNativeX3dhSender({
    senderKey1: senderX3dhKey1,
    senderKey2: senderX3dhKey2,
    recipientKey1: recipientE2eKey1,
    recipientKey2: recipientE2eKey2
  });
  var nativeRatchet = createNativeSendingRatchet({
    version: options.nativeE2EVersion || SIMPLEX_NATIVE_E2E_VERSION,
    init,
    ownDhKey: senderRatchetDh,
    remoteDhPublicKey: recipientE2eKey1.rawPublicKey
  });
  var connInfo = options.connInfo == null
    ? nativeProfileConnInfo(options.profile || {})
    : toBytes(options.connInfo, 'native connection info');
  var agentConnInfo = encodeNativeAgentConnInfo({
    type: 'reply',
    replyQueues: [options.replyQueue],
    connInfo
  });
  var encryptedConnInfo = encryptNativeRatchetMessage(nativeRatchet, agentConnInfo, {
    paddedLength: options.encConnInfoLength || SIMPLEX_NATIVE_ENC_CONN_INFO_LENGTH,
    headerIv: options.nativeHeaderIv
  });
  var e2eEncryption = encodeNativeE2ERatchetParams({
    version: options.nativeE2EVersion || SIMPLEX_NATIVE_E2E_VERSION,
    key1: senderX3dhKey1,
    key2: senderX3dhKey2
  });
  var body = encodeNativeAgentEnvelope({
    type: 'confirmation',
    version: options.nativeAgentVersion || SIMPLEX_NATIVE_AGENT_MESSAGE_VERSION,
    e2eEncryption,
    encConnInfo: encryptedConnInfo.packet
  });
  var shared = x25519SharedSecret(senderQueueDh.secretKey, recipientQueueDh.rawPublicKey);
  var prepared = prepareInitialSenderMessage({
    version: options.version || 4,
    sessionId: options.sessionId || new Uint8Array(),
    corrId: options.corrId || new Uint8Array(),
    senderQueueId: invitationQueue.queueId,
    senderSignKey: options.senderSignKey,
    senderSignSeed: options.senderSignSeed,
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderQueueDh.publicKeyDer,
    nonce: options.nonce,
    body,
    flags: options.flags
  });
  return {
    ...prepared,
    link,
    invitationQueue,
    perQueueSharedSecret: shared,
    senderQueueDh,
    senderX3dhKey1,
    senderX3dhKey2,
    senderRatchetDh,
    nativeRatchet: encryptedConnInfo.state,
    e2eEncryption,
    encConnInfo: encryptedConnInfo.packet,
    agentEnvelope: body
  };
}

export function prepareSenderMessage(queue, options = {}) {
  // After contact confirmation, ordinary sender messages use the sender queue
  // ID. If a sender signing key is present the SMP transmission is signed;
  // otherwise it remains unsigned for pre-secure test and bootstrap flows.
  var q = queue && typeof queue === 'object' ? queue : {};
  if (!q.sndId) fail('SIMPLEX_AGENT_QUEUE', 'sender queue id is missing');
  var command = {
    type: 'SEND',
    flags: options.flags || { notification: false },
    body: toBytes(options.body || new Uint8Array(), 'sender message body')
  };
  var tx = {
    corrId: options.corrId || new Uint8Array(),
    queueId: q.sndId,
    command
  };
  if (q.senderSignKey && q.senderSignKey.secretKey) tx.privateKey = q.senderSignKey.secretKey;
  else tx.signature = new Uint8Array();
  return encodeSignedTransmission(options.version || 4, options.sessionId || new Uint8Array(), tx);
}

export function inspectSignedCommand(version, signedTransmission) {
  var parsed = parseSignedTransmission(version || 4, signedTransmission.bytes || signedTransmission);
  return {
    signature: parsed.signature,
    signed: parsed.signed,
    sessionId: parsed.sessionId,
    corrId: parsed.corrId,
    queueId: parsed.queueId,
    command: parsed.command || parseCommand(version || 4, parsed.commandBytes)
  };
}

export function inspectBrokerBytes(version, brokerMessage) {
  return parseBrokerMessage(version || 4, encodeBrokerMessage(version || 4, brokerMessage));
}

export function queueSummary(queue) {
  var q = queue && typeof queue === 'object' ? queue : {};
  return {
    hasServer: !!q.server,
    rcvIdLength: q.rcvId ? toBytes(q.rcvId).length : 0,
    sndIdLength: q.sndId ? toBytes(q.sndId).length : 0,
    hasRecipientSigningKey: !!(q.rcvSignKey && q.rcvSignKey.publicKey),
    hasRecipientDhSecret: !!q.serverDhSecret
  };
}

export default {
  SIMPLEX_AGENT_MESSAGE_VERSION,
  SIMPLEX_CONFIRMATION_PRIVATE_HEADER,
  SIMPLEX_EMPTY_PRIVATE_HEADER,
  SIMPLEX_NATIVE_AGENT_MESSAGE_VERSION,
  SIMPLEX_NATIVE_E2E_VERSION,
  SIMPLEX_NATIVE_ENC_CONN_INFO_LENGTH,
  completeNewQueueRequest,
  deriveNativeX3dhReceiver,
  deriveNativeX3dhSender,
  decryptClientMessageEnvelope,
  decryptRcvMessageBody,
  encodeClientMessage,
  encodeClientMessageEnvelope,
  encodePrivateHeader,
  encodePublicHeader,
  encodeRcvMessageBody,
  encryptClientMessage,
  encryptRcvMessageBody,
  inspectBrokerBytes,
  inspectSignedCommand,
  messageIdNonce,
  encodeNativeAgentEnvelope,
  encodeNativeAgentConnInfo,
  encodeNativeAgentMessage,
  encodeNativeE2ERatchetParams,
  encodeNativeSmpQueueInfo,
  parseClientMessage,
  parseClientMessageEnvelope,
  parseNativeAgentEnvelope,
  parseNativeAgentConnInfo,
  parseNativeAgentMessage,
  parseNativeE2ERatchetParams,
  parsePrivateHeader,
  parsePublicHeader,
  parseRcvMessageBody,
  prepareInitialSenderMessage,
  prepareNativeContactRequest,
  prepareNativeInvitationJoin,
  prepareNewQueueRequest,
  prepareRecipientCommand,
  prepareSenderMessage,
  queueSummary,
  equalBytes,
  asciiText
};
