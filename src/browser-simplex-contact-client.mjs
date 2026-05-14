// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser contact client layer.
//
// This module combines the queue client, durable store, retry scheduler, and
// ratchet helpers into a full browser-owned contact state machine. It keeps the
// policy visible: contacts have explicit states, sends require an active
// ratchet, and failed sends become durable encrypted-packet retry tasks instead
// of disappearing or storing chat plaintext.

import {
  concatBytes,
  decodeBase64Url,
  decodePublicKeyDer,
  encodeBase64Url,
  generateEd25519KeyPair,
  formatSmpQueueUri,
  generateX25519KeyPair,
  parseSimplexConnectionLink,
  parseSmpQueueUri,
  randomNonce24,
  sha256Hash,
  toBytes,
  utf8Bytes,
  utf8Text,
  x25519SharedSecret
} from './browser-smp-core.mjs';
import { createBrowserSimplexClient } from './browser-simplex-client.mjs';
import { createBrowserSimplexStore } from './browser-simplex-store.mjs';
import { createBrowserSimplexRetryScheduler } from './browser-simplex-scheduler.mjs';
import {
  decryptClientMessageEnvelope,
  decryptRcvMessageBody,
  deriveNativeX3dhReceiver,
  encryptClientMessage,
  encodeNativeAgentEnvelope,
  encodeNativeAgentConnInfo,
  encodeNativeAgentMessage,
  parseClientMessageEnvelope,
  parseNativeAgentConnInfo,
  parseNativeAgentEnvelope,
  parseNativeAgentMessage,
  parseNativeE2ERatchetParams,
  SIMPLEX_NATIVE_ENC_CONN_INFO_LENGTH,
  SIMPLEX_NATIVE_E2E_VERSION
} from './browser-simplex-agent.mjs';
import { createRatchetState, decryptRatchetMessage, encryptRatchetMessage } from './browser-simplex-ratchet.mjs';
import { createNativeReceivingRatchet, decryptNativeRatchetMessage, encryptNativeRatchetMessage } from './browser-simplex-native-ratchet.mjs';
import { createBrowserXftpClient } from './browser-xftp-client.mjs';

export const CONTACT_STATE_INVITED = 'invited';
export const CONTACT_STATE_REQUESTED = 'requested';
export const CONTACT_STATE_ACTIVE = 'active';
export const CONTACT_STATE_SUSPENDED = 'suspended';
export const CONTACT_STATE_DELETED = 'deleted';
export const CONTACT_PAYLOAD_PREFIX = 'simplex-web:payload:v1\n';
const MAX_MESSAGE_REF_LENGTH = 256;
const NATIVE_AGENT_MESSAGE_PADDED_LENGTH = 14800;

export class BrowserSimplexContactError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSimplexContactError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserSimplexContactError(code, message);
}

function safeId(value, label = 'contact id') {
  var text = String(value == null ? '' : value).trim();
  if (!text || text.length > 160 || /[^A-Za-z0-9_.:-]/.test(text)) fail('SIMPLEX_CONTACT_ID', label + ' is invalid');
  return text;
}

function safeStoredId(value, fallback) {
  try {
    return value == null ? fallback : safeId(value, 'stored contact record id');
  } catch (_error) {
    return fallback;
  }
}

function safeMessageRef(value, label = 'message ref') {
  var text = String(value == null ? '' : value).trim();
  if (!text || text.length > MAX_MESSAGE_REF_LENGTH || /[^A-Za-z0-9_.:-]/.test(text)) {
    fail('SIMPLEX_CONTACT_MESSAGE_REF', label + ' is invalid');
  }
  return text;
}

function optionalMessageRef(value, label = 'message ref') {
  return value == null || value === '' ? '' : safeMessageRef(value, label);
}

function nowIso() {
  return new Date().toISOString();
}

function requireState(contact, allowed) {
  if (!contact || !allowed.includes(contact.state)) {
    fail('SIMPLEX_CONTACT_STATE', 'contact state does not allow this operation');
  }
}

function packetBytes(packet) {
  return utf8Bytes(JSON.stringify({
    h: Array.from(packet.header),
    n: Array.from(packet.nonce),
    c: Array.from(packet.ciphertext),
    t: Array.from(packet.tag)
  }));
}

function parsePacketBytes(bytes) {
  var parsed = JSON.parse(utf8Text(bytes));
  return {
    header: new Uint8Array(parsed.h || []),
    nonce: new Uint8Array(parsed.n || []),
    ciphertext: new Uint8Array(parsed.c || []),
    tag: new Uint8Array(parsed.t || [])
  };
}

export function encodeContactPayload(payload = {}) {
  var p = payload && typeof payload === 'object' ? payload : {};
  return CONTACT_PAYLOAD_PREFIX + JSON.stringify(p);
}

function validateTextPayload(parsed) {
  var text = String(parsed.text == null ? '' : parsed.text);
  var messageRef = optionalMessageRef(parsed.messageRef || parsed.message_ref || '');
  return {
    type: 'text',
    text,
    messageRef,
    createdAt: String(parsed.createdAt || parsed.created_at || '').slice(0, 64)
  };
}

function validateFilePayload(parsed) {
  if (!parsed.file || typeof parsed.file !== 'object') fail('SIMPLEX_CONTACT_PAYLOAD', 'contact file payload is invalid');
  return {
    type: 'file',
    file: parsed.file,
    messageRef: optionalMessageRef(parsed.messageRef || parsed.message_ref || ''),
    createdAt: String(parsed.createdAt || parsed.created_at || '').slice(0, 64)
  };
}

function validateReadReceiptPayload(parsed) {
  return {
    type: 'read-receipt',
    messageRef: safeMessageRef(parsed.messageRef || parsed.message_ref, 'read receipt message ref'),
    readAt: String(parsed.readAt || parsed.read_at || nowIso()).slice(0, 64)
  };
}

export function decodeContactPayload(text) {
  var value = String(text == null ? '' : text);
  if (!value.startsWith(CONTACT_PAYLOAD_PREFIX)) return { type: 'text', text: value };
  var parsed;
  try {
    parsed = JSON.parse(value.slice(CONTACT_PAYLOAD_PREFIX.length));
  } catch (_error) {
    fail('SIMPLEX_CONTACT_PAYLOAD', 'contact payload JSON is invalid');
  }
  if (!parsed || typeof parsed !== 'object') fail('SIMPLEX_CONTACT_PAYLOAD', 'contact payload is invalid');
  if (parsed.type === 'text') return validateTextPayload(parsed);
  if (parsed.type === 'file') return validateFilePayload(parsed);
  if (parsed.type === 'read-receipt') return validateReadReceiptPayload(parsed);
  fail('SIMPLEX_CONTACT_PAYLOAD', 'contact payload type is unsupported');
}

function encodeNativeChatBody(plaintext) {
  var text = utf8Text(toBytes(plaintext, 'native chat plaintext'));
  var payload = decodeContactPayload(text);
  if (payload.type === 'text') {
    return utf8Bytes(JSON.stringify({
      v: '1',
      event: 'x.msg.new',
      params: {
        content: {
          type: 'text',
          text: payload.text
        }
      }
    }));
  }
  if (payload.type === 'file') {
    fail(
      'SIMPLEX_CONTACT_NATIVE_FILE',
      'native SimpleX file attachments require native XFTP file invitations and are not implemented yet'
    );
  }
  return utf8Bytes(JSON.stringify({
    v: '1',
    event: 'x.msg.new',
    params: {
      content: {
        type: 'text',
        text
      }
    }
  }));
}

function decodeNativeChatBody(bytes) {
  var text = utf8Text(toBytes(bytes, 'native chat body'));
  try {
    var parsed = JSON.parse(text);
    var content = parsed && parsed.params && parsed.params.content;
    if (parsed && parsed.event === 'x.msg.new' && content && typeof content === 'object') {
      if (content.type === 'text') return { text: String(content.text == null ? '' : content.text), payload: { type: 'text', text: String(content.text == null ? '' : content.text), messageRef: '', createdAt: '' } };
      if (content.type === 'file') return { text: String(content.text == null ? '' : content.text), payload: { type: 'file', file: { name: String(content.text == null ? '' : content.text) }, messageRef: '', createdAt: '' } };
    }
  } catch (_error) {
    // simplex-web peers may still send the private payload envelope; fall back
    // to that decoder so mixed browser-native conversations remain readable.
  }
  var payload = decodeContactPayload(text);
  return { text: payload.type === 'text' ? payload.text : text, payload };
}

function requireXftpClient(client) {
  if (!client || typeof client.uploadFile !== 'function' || typeof client.downloadFile !== 'function') {
    fail('SIMPLEX_CONTACT_XFTP', 'contact file transfer requires a browser XFTP client');
  }
  return client;
}

function invitationUriFromQueue(queue) {
  if (!queue || !queue.server) fail('SIMPLEX_CONTACT_INVITATION', 'contact invitation requires server identity');
  return formatSmpQueueUri({
    server: queue.server,
    queueId: queue.sndId,
    recipientDhPublicKey: queue.rcvDhKey.publicKeyDer
  });
}

function maybeInvitationUriFromQueue(queue) {
  return queue && queue.server ? invitationUriFromQueue(queue) : '';
}

function parseJsonBytes(bytes, label) {
  try {
    return JSON.parse(utf8Text(bytes));
  } catch (_error) {
    fail('SIMPLEX_CONTACT_JSON', label + ' JSON is invalid');
  }
}

function profileFromNativeConnInfo(bytes) {
  var decoded = parseJsonBytes(bytes, 'native contact info') || {};
  if (decoded.event === 'x.info' && decoded.params && typeof decoded.params === 'object') {
    return decoded.params.profile && typeof decoded.params.profile === 'object' ? decoded.params.profile : {};
  }
  return decoded && typeof decoded === 'object' ? decoded : {};
}

function nativeProfileConnInfo(profile = {}) {
  var input = profile && typeof profile === 'object' ? profile : {};
  var displayName = String(input.displayName || input.display_name || input.fullName || input.full_name || 'simplex-web').trim() || 'simplex-web';
  var fullName = String(input.fullName || input.full_name || displayName).trim();
  return utf8Bytes(JSON.stringify({
    event: 'x.info',
    params: {
      profile: {
        ...input,
        displayName,
        fullName
      }
    }
  }));
}

function ackTaskId(contactId, msgId) {
  return 'ack:' + encodeBase64Url(msgId).slice(0, 96) + ':' + encodeBase64Url(utf8Bytes(safeId(contactId))).slice(0, 48);
}

function initialConfirmationTaskId(contactId, corrId) {
  return safeId(contactId) + ':initial:' + encodeBase64Url(corrId).slice(0, 64);
}

function receivedRecordId(contactId, msgId) {
  var digest = sha256Hash(concatBytes(
    utf8Bytes(safeId(contactId)),
    new Uint8Array([0]),
    toBytes(msgId, 'received message id')
  ));
  return 'rx:' + encodeBase64Url(digest);
}

function receivedBodyHash(body) {
  return encodeBase64Url(sha256Hash(toBytes(body || new Uint8Array(), 'received encrypted body')));
}

function retryBytes(value, label) {
  return typeof value === 'string' ? decodeBase64Url(value, label) : toBytes(value, label);
}

function normalizeNativeReceiptMessageId(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  var text = String(value == null ? '' : value).trim();
  if (!/^[0-9]+$/.test(text)) fail('SIMPLEX_CONTACT_RECEIPT', 'native receipt message id is invalid');
  return BigInt(text);
}

function normalizeNativeReceiptHash(value) {
  var hash = retryBytes(value, 'native receipt message hash');
  if (hash.length !== 32) fail('SIMPLEX_CONTACT_RECEIPT', 'native receipt message hash must be 32 bytes');
  return hash;
}

function prepareNativeOutboundQueue(queue, options = {}) {
  var q = { ...(queue || {}) };
  if (q.e2eSharedSecret && q.senderE2eKey) return q;
  var recipientDh = decodePublicKeyDer(q.recipientDhPublicKey || q.dhPublicKey);
  if (recipientDh.algorithm !== 'X25519') fail('SIMPLEX_CONTACT_NATIVE_QUEUE', 'native outbound queue DH key must be X25519');
  var senderE2eKey = options.senderE2eKey || options.senderE2eDhKey || generateX25519KeyPair(options.senderE2eSeed || options.replySenderE2eSeed);
  return {
    ...q,
    senderE2eKey,
    e2eSharedSecret: x25519SharedSecret(senderE2eKey.secretKey, recipientDh.rawPublicKey),
    nativeE2ePubDhKeyPending: q.nativeE2ePubDhKeyPending !== false,
    smpClientVersion: Number(q.smpClientVersion || options.smpClientVersion || 4)
  };
}

function encodeNativeQueueClientMessage(queue, nativeAgentEnvelope, options = {}) {
  var q = prepareNativeOutboundQueue(queue, options);
  var includeSenderDh = q.nativeE2ePubDhKeyPending !== false;
  return {
    queue: {
      ...q,
      nativeE2ePubDhKeyPending: false
    },
    body: encryptClientMessage({
      sharedSecret: q.e2eSharedSecret,
      nonce: options.clientNonce || options.nativeClientNonce || randomNonce24(),
      publicHeader: {
        version: q.smpClientVersion || options.smpClientVersion || 4,
        e2ePubDhKey: includeSenderDh ? q.senderE2eKey.publicKeyDer : null
      },
      privateHeader: { type: 'empty' },
      body: nativeAgentEnvelope
    })
  };
}

function outboxQueueId(contact) {
  return contact.outboxQueueId || (contact.id + ':outbox');
}

function uniqueIds(ids) {
  var out = [];
  for (var id of ids) {
    if (id && !out.includes(id)) out.push(id);
  }
  return out;
}

function ownedInboxQueueIds(contact, cleanId) {
  var fallback = cleanId + ':inbox';
  return uniqueIds([
    safeStoredId(contact && contact.inboxQueueId, fallback),
    fallback
  ]);
}

function deleteQueueOptions(options, queueId, index, client) {
  var corrId = null;
  if (Array.isArray(options.corrIds)) corrId = options.corrIds[index];
  if (!corrId && options.corrIds && typeof options.corrIds === 'object') corrId = options.corrIds[queueId];
  if (!corrId && index === 0) corrId = options.corrId;
  if (!corrId) corrId = client.makeCorrId('del');
  return { ...options, corrId };
}

export function createBrowserSimplexContactClient(options = {}) {
  return new BrowserSimplexContactClient(options);
}

export class BrowserSimplexContactClient {
  constructor(options = {}) {
    this.client = options.client || createBrowserSimplexClient(options);
    this.store = options.store || createBrowserSimplexStore(options.storeOptions || {});
    this.scheduler = options.scheduler || createBrowserSimplexRetryScheduler({ store: this.store });
    this.xftpClient = options.xftpClient || (options.xftpServer ? createBrowserXftpClient({ server: options.xftpServer, profile: options.xftpProfile }) : null);
  }

  async createInvitation(options = {}) {
    var id = safeId(options.id || ('contact-' + Date.now()));
    var queue = await this.client.createQueue({
      label: id + ':inbox',
      corrId: options.corrId,
      rcvSignSeed: options.rcvSignSeed,
      rcvDhSeed: options.rcvDhSeed,
      server: options.server
    });
    this.store.saveQueue(id + ':inbox', queue);
    var contact = {
      id,
      state: CONTACT_STATE_INVITED,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      inboxQueueId: id + ':inbox',
      invitationUri: maybeInvitationUriFromQueue(queue),
      profile: options.profile || {},
      outboundQueue: null
    };
    this.store.saveContact(id, contact);
    return contact;
  }

  invitationUri(id) {
    var contact = this.store.loadContact(safeId(id));
    if (!contact) fail('SIMPLEX_CONTACT_MISSING', 'contact does not exist');
    if (contact.invitationUri) return contact.invitationUri;
    var queue = this.store.loadQueue(contact.inboxQueueId || (contact.id + ':inbox'));
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'contact inbox queue is missing');
    return invitationUriFromQueue(queue);
  }

  async requestContact(id, invitationUri, options = {}) {
    var cleanId = safeId(id);
    var link = parseSimplexConnectionLink(invitationUri);
    if (link.nativeAgentProfile) {
      if (options.allowNativeAgentProfile !== true) {
        fail(
          'SIMPLEX_CONTACT_NATIVE_AGENT_UNSUPPORTED',
          'native SimpleX Chat invitation links require allowNativeAgentProfile while the native browser agent is being completed'
        );
      }
      return this.requestNativeContact(cleanId, String(invitationUri), link, options);
    }
    var parsed = link.smpQueues[0] || parseSmpQueueUri(invitationUri);
    var recipientDh = decodePublicKeyDer(parsed.recipientDhPublicKey);
    if (recipientDh.algorithm !== 'X25519') fail('SIMPLEX_CONTACT_INVITATION', 'contact invitation DH key must be X25519');
    var replyQueue = options.replyQueue || null;
    if (!replyQueue && options.createReplyQueue !== false) {
      replyQueue = await this.client.createQueue({
        label: cleanId + ':inbox',
        corrId: options.replyCorrId || options.reply_corr_id || this.client.makeCorrId('reply'),
        rcvSignSeed: options.replyRcvSignSeed,
        rcvDhSeed: options.replyRcvDhSeed,
        server: options.replyServer || parsed.server
      });
    }
    if (replyQueue) this.store.saveQueue(cleanId + ':inbox', replyQueue);
    var ownDhKey = options.ownDhKey || generateX25519KeyPair(options.ownDhSeed);
    var shared = x25519SharedSecret(ownDhKey.secretKey, recipientDh.rawPublicKey);
    var body = utf8Bytes(JSON.stringify({
      type: 'contact-request',
      profile: options.profile || {},
      replyQueueUri: replyQueue ? invitationUriFromQueue(replyQueue) : '',
      createdAt: nowIso()
    }));
    var prepared = this.client.prepareInitialConfirmation({
      corrId: options.corrId,
      senderQueueId: parsed.queueId,
      senderSignKey: options.senderSignKey,
      senderSignSeed: options.senderSignSeed,
      e2eSharedSecret: shared,
      senderE2ePubDhKey: ownDhKey.publicKeyDer,
      nonce: options.nonce,
      body,
      flags: options.flags
    });
    var contact = {
      id: cleanId,
      state: CONTACT_STATE_REQUESTED,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      invitationUri: String(invitationUri),
      inboxQueueId: replyQueue ? cleanId + ':inbox' : '',
      profile: options.profile || {},
      outboundQueue: {
        server: parsed.server,
        sndId: parsed.queueId,
        senderSignKey: prepared.senderSignKey
      }
    };
    this.store.saveContact(cleanId, contact);
    this.store.saveQueue(cleanId + ':outbox', contact.outboundQueue);
    this.store.saveRatchet(cleanId, createRatchetState({
      rootKey: shared,
      ownDhKey,
      remoteDhPublicKey: recipientDh.rawPublicKey
    }));
    var taskId = initialConfirmationTaskId(cleanId, prepared.corrId);
    try {
      await this.client.sendPreparedInitialConfirmation(prepared, options);
      this.scheduler.complete(taskId);
    } catch (error) {
      if (options.retryOnFailure !== false) {
        // Initial contact requests are retried as the already-encrypted
        // unsigned SMP SEND. The retry task never stores profile JSON or other
        // plaintext request material.
        this.scheduler.enqueue(taskId, {
          type: 'initialConfirmation',
          contactId: cleanId,
          transmission: prepared.transmission.bytes,
          corrId: prepared.corrId,
          options: { timeoutMs: options.timeoutMs || 0 }
        });
        this.scheduler.fail(taskId, error);
      }
      throw error;
    }
    return contact;
  }

  async requestNativeContact(cleanId, invitationUri, link, options = {}) {
    var parsed = link.smpQueues[0];
    if (!parsed) fail('SIMPLEX_CONTACT_INVITATION', 'native invitation does not contain an SMP queue');
    var replyQueue = options.replyQueue || null;
    if (!replyQueue && options.createReplyQueue !== false) {
      replyQueue = await this.client.createQueue({
        label: cleanId + ':inbox',
        corrId: options.replyCorrId || options.reply_corr_id || this.client.makeCorrId('reply'),
        rcvSignSeed: options.replyRcvSignSeed,
        rcvDhSeed: options.replyRcvDhSeed,
        server: options.replyServer || parsed.server
      });
    }
    if (!replyQueue) {
      fail('SIMPLEX_CONTACT_NATIVE_AGENT_UNSUPPORTED', 'native SimpleX invitation joins require a reply queue');
    }
    this.store.saveQueue(cleanId + ':inbox', replyQueue);
    var isContactAddress = link.type === 'contact';
    var prepared = isContactAddress
      ? this.client.prepareNativeContactRequest({
        ...options,
        link,
        invitationUri,
        replyQueue,
        profile: options.profile || {}
      })
      : this.client.prepareNativeInvitationJoin({
        ...options,
        link,
        invitationUri,
        replyQueue,
        profile: options.profile || {}
      });
    var contact = {
      id: cleanId,
      state: CONTACT_STATE_REQUESTED,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      invitationUri,
      inboxQueueId: cleanId + ':inbox',
      profile: options.profile || {},
      nativeAgentProfile: true,
      nativeContactAddress: isContactAddress,
      outboundQueue: {
        server: parsed.server,
        sndId: parsed.queueId,
        senderSignKey: prepared.senderSignKey,
        recipientDhPublicKey: parsed.recipientDhPublicKey,
        queueMode: parsed.native && parsed.native.queueMode,
        nativeRatchet: prepared.nativeRatchet || null,
        senderX3dhPublicKey1: prepared.senderX3dhKey1 ? prepared.senderX3dhKey1.publicKey : null,
        senderX3dhPublicKey2: prepared.senderX3dhKey2 ? prepared.senderX3dhKey2.publicKey : null
      }
    };
    this.store.saveContact(cleanId, contact);
    this.store.saveQueue(cleanId + ':outbox', contact.outboundQueue);
    this.store.saveRatchet(cleanId, isContactAddress ? {
      nativeAgentProfile: true,
      pendingNativeContactRequest: true,
      recipientX3dhKey1: prepared.recipientX3dhKey1,
      recipientX3dhKey2: prepared.recipientX3dhKey2,
      senderSignKey: prepared.senderSignKey
    } : {
      nativeAgentProfile: true,
      ...prepared.nativeRatchet
    });
    var taskId = initialConfirmationTaskId(cleanId, prepared.corrId);
    try {
      await this.client.sendPreparedInitialConfirmation(prepared, options);
      this.scheduler.complete(taskId);
    } catch (error) {
      if (options.retryOnFailure !== false) {
        this.scheduler.enqueue(taskId, {
          type: 'initialConfirmation',
          contactId: cleanId,
          transmission: prepared.transmission.bytes,
          corrId: prepared.corrId,
          options: { timeoutMs: options.timeoutMs || 0 }
        });
        this.scheduler.fail(taskId, error);
      }
      throw error;
    }
    return contact;
  }

  async receiveContactRequest(id, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    requireState(contact, [CONTACT_STATE_INVITED]);
    var queue = options.queue || this.store.loadQueue(contact.inboxQueueId || (contact.id + ':inbox'));
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'contact inbox queue is missing');
    var received = await this.client.receiveQueueMessage(queue, options);
    var decryptedBody = decryptRcvMessageBody({
      serverDhSecret: queue.serverDhSecret,
      msgId: received.message.msgId,
      encryptedBody: received.message.body
    });
    var envelope = parseClientMessageEnvelope(decryptedBody.body);
    if (!envelope.publicHeader.e2ePubDhKey) fail('SIMPLEX_CONTACT_REQUEST', 'contact request is missing sender E2E DH key');
    var senderDh = decodePublicKeyDer(envelope.publicHeader.e2ePubDhKey);
    if (senderDh.algorithm !== 'X25519') fail('SIMPLEX_CONTACT_REQUEST', 'contact request sender DH key must be X25519');
    var shared = x25519SharedSecret(queue.rcvDhKey.secretKey, senderDh.rawPublicKey);
    var decrypted = decryptClientMessageEnvelope({
      sharedSecret: shared,
      envelope: decryptedBody.body
    });
    if (decrypted.privateHeader.type !== 'confirmation') fail('SIMPLEX_CONTACT_REQUEST', 'contact request is missing confirmation key');
    var request = parseJsonBytes(decrypted.body, 'contact request');
    if (!request || request.type !== 'contact-request') fail('SIMPLEX_CONTACT_REQUEST', 'contact request payload is unsupported');
    var acceptReply = null;
    if (request.replyQueueUri && options.sendAccept !== false) {
      var reply = parseSmpQueueUri(request.replyQueueUri);
      var replyDh = decodePublicKeyDer(reply.recipientDhPublicKey);
      if (replyDh.algorithm !== 'X25519') fail('SIMPLEX_CONTACT_ACCEPT', 'contact accept reply queue DH key must be X25519');
      acceptReply = { reply, replyDh };
    }
    await this.client.secureQueue(queue, decrypted.privateHeader.senderPublicVerifyKey, {
      ...options,
      corrId: options.keyCorrId || options.corrId || ('key-' + Date.now())
    });
    contact.state = CONTACT_STATE_ACTIVE;
    contact.updatedAt = nowIso();
    contact.remoteProfile = request.profile || {};
    contact.inboundSenderPublicVerifyKey = decrypted.privateHeader.senderPublicVerifyKey;
    var accept = null;
    var preparedAccept = null;
    var acceptTaskId = '';
    if (acceptReply) {
      var reply = acceptReply.reply;
      var replyDh = acceptReply.replyDh;
      var acceptDh = options.acceptDhKey || generateX25519KeyPair(options.acceptDhSeed);
      var acceptShared = x25519SharedSecret(acceptDh.secretKey, replyDh.rawPublicKey);
      var acceptBody = utf8Bytes(JSON.stringify({
        type: 'contact-accept',
        profile: options.acceptProfile || contact.profile || {},
        createdAt: nowIso()
      }));
      preparedAccept = this.client.prepareInitialConfirmation({
        corrId: options.acceptCorrId || options.replyCorrId || ('accept-' + Date.now()),
        senderQueueId: reply.queueId,
        senderSignKey: options.acceptSenderSignKey,
        senderSignSeed: options.acceptSenderSignSeed,
        e2eSharedSecret: acceptShared,
        senderE2ePubDhKey: acceptDh.publicKeyDer,
        nonce: options.acceptNonce,
        body: acceptBody,
        flags: options.flags
      });
      contact.outboundQueue = {
        server: reply.server,
        sndId: reply.queueId,
        senderSignKey: preparedAccept.senderSignKey
      };
      contact.outboxQueueId = contact.id + ':outbox';
      this.store.saveQueue(contact.outboxQueueId, contact.outboundQueue);
      acceptTaskId = initialConfirmationTaskId(contact.id, preparedAccept.corrId);
    }
    this.store.saveContact(contact.id, contact);
    this.store.saveRatchet(contact.id, createRatchetState({
      rootKey: shared,
      ownDhKey: queue.rcvDhKey,
      // Do not pre-fill the remote ratchet key here. The first ordinary
      // requester message carries that key in its ratchet header; leaving it
      // unset makes the receiver derive the receiving chain on that message.
      initializeSending: false
    }));
    var ack = await this.acknowledgeOrQueue(contact, queue, received.message.msgId, {
      ...options,
      corrId: options.ackCorrId || options.corrId || ('ack-' + Date.now())
    });
    if (preparedAccept) {
      try {
        accept = await this.client.sendPreparedInitialConfirmation(preparedAccept, options);
        this.scheduler.complete(acceptTaskId);
      } catch (error) {
        if (options.retryOnFailure !== false) {
          // Accept confirmations use the same encrypted initial SEND shape as
          // contact requests, so retry only the already-encrypted wire bytes.
          this.scheduler.enqueue(acceptTaskId, {
            type: 'initialConfirmation',
            contactId: contact.id,
            transmission: preparedAccept.transmission.bytes,
            corrId: preparedAccept.corrId,
            options: { timeoutMs: options.timeoutMs || 0 }
          });
          this.scheduler.fail(acceptTaskId, error);
        }
        throw error;
      }
    }
    return {
      contact,
      request,
      accept,
      msgId: received.message.msgId,
      timestamp: decryptedBody.timestamp,
      ...ack
    };
  }

  async receiveContactAccept(id, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    requireState(contact, [CONTACT_STATE_REQUESTED, CONTACT_STATE_ACTIVE]);
    if (contact.nativeAgentProfile) return this.receiveNativeContactAccept(contact, options);
    var queue = options.queue || this.store.loadQueue(contact.inboxQueueId || (contact.id + ':inbox'));
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'contact accept queue is missing');
    var received = await this.client.receiveQueueMessage(queue, options);
    var decryptedBody = decryptRcvMessageBody({
      serverDhSecret: queue.serverDhSecret,
      msgId: received.message.msgId,
      encryptedBody: received.message.body
    });
    var envelope = parseClientMessageEnvelope(decryptedBody.body);
    if (!envelope.publicHeader.e2ePubDhKey) fail('SIMPLEX_CONTACT_ACCEPT', 'contact accept is missing sender E2E DH key');
    var senderDh = decodePublicKeyDer(envelope.publicHeader.e2ePubDhKey);
    if (senderDh.algorithm !== 'X25519') fail('SIMPLEX_CONTACT_ACCEPT', 'contact accept sender DH key must be X25519');
    var shared = x25519SharedSecret(queue.rcvDhKey.secretKey, senderDh.rawPublicKey);
    var decrypted = decryptClientMessageEnvelope({
      sharedSecret: shared,
      envelope: decryptedBody.body
    });
    if (decrypted.privateHeader.type !== 'confirmation') fail('SIMPLEX_CONTACT_ACCEPT', 'contact accept is missing confirmation key');
    var accept = parseJsonBytes(decrypted.body, 'contact accept');
    if (!accept || accept.type !== 'contact-accept') fail('SIMPLEX_CONTACT_ACCEPT', 'contact accept payload is unsupported');
    await this.client.secureQueue(queue, decrypted.privateHeader.senderPublicVerifyKey, {
      ...options,
      corrId: options.keyCorrId || options.corrId || ('accept-key-' + Date.now())
    });
    contact.state = CONTACT_STATE_ACTIVE;
    contact.updatedAt = nowIso();
    contact.remoteProfile = accept.profile || {};
    contact.inboundSenderPublicVerifyKey = decrypted.privateHeader.senderPublicVerifyKey;
    this.store.saveContact(contact.id, contact);
    var ack = await this.acknowledgeOrQueue(contact, queue, received.message.msgId, {
      ...options,
      corrId: options.ackCorrId || options.corrId || ('accept-ack-' + Date.now())
    });
    return {
      contact,
      accept,
      msgId: received.message.msgId,
      timestamp: decryptedBody.timestamp,
      ...ack
    };
  }

  async receiveNativeContactAccept(contact, options = {}) {
    var queue = options.queue || this.store.loadQueue(contact.inboxQueueId || (contact.id + ':inbox'));
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'native contact accept queue is missing');
    var received = await this.client.receiveQueueMessage(queue, options);
    var decryptedBody = decryptRcvMessageBody({
      serverDhSecret: queue.serverDhSecret,
      msgId: received.message.msgId,
      encryptedBody: received.message.body
    });
    var envelope = parseClientMessageEnvelope(decryptedBody.body);
    if (!envelope.publicHeader.e2ePubDhKey) fail('SIMPLEX_CONTACT_ACCEPT', 'native accept is missing sender E2E DH key');
    var senderDh = decodePublicKeyDer(envelope.publicHeader.e2ePubDhKey);
    if (senderDh.algorithm !== 'X25519') fail('SIMPLEX_CONTACT_ACCEPT', 'native accept sender DH key must be X25519');
    var inboundShared = x25519SharedSecret(queue.rcvDhKey.secretKey, senderDh.rawPublicKey);
    var decrypted = decryptClientMessageEnvelope({
      sharedSecret: inboundShared,
      envelope: decryptedBody.body
    });
    if (decrypted.privateHeader.type !== 'confirmation' && decrypted.privateHeader.type !== 'empty') {
      fail('SIMPLEX_CONTACT_ACCEPT', 'native accept has an unsupported private header');
    }
    var nativeEnvelope = parseNativeAgentEnvelope(decrypted.body);
    if (nativeEnvelope.type !== 'confirmation') fail('SIMPLEX_CONTACT_ACCEPT', 'native accept envelope must be a confirmation');
    var storedRatchet = this.store.loadRatchet(contact.id);
    if (!storedRatchet || !storedRatchet.nativeAgentProfile) fail('SIMPLEX_CONTACT_RATCHET', 'native contact ratchet is missing');
    var ratchet = storedRatchet;
    var nativePlain = null;
    if (nativeEnvelope.e2eEncryption) {
      if (!ratchet.pendingNativeContactRequest || !ratchet.recipientX3dhKey1 || !ratchet.recipientX3dhKey2) {
        fail('SIMPLEX_CONTACT_RATCHET', 'native contact request keys are missing');
      }
      var e2e = parseNativeE2ERatchetParams(nativeEnvelope.e2eEncryption);
      var init = deriveNativeX3dhReceiver({
        recipientKey1: ratchet.recipientX3dhKey1,
        recipientKey2: ratchet.recipientX3dhKey2,
        senderKey1: e2e.key1,
        senderKey2: e2e.key2
      });
      var receivingRatchet = createNativeReceivingRatchet({
        version: e2e.version || SIMPLEX_NATIVE_E2E_VERSION,
        init,
        ownDhKey: ratchet.recipientX3dhKey2
      });
      nativePlain = decryptNativeRatchetMessage(receivingRatchet, nativeEnvelope.encConnInfo);
      ratchet = nativePlain.state;
    }
    if (!nativePlain) nativePlain = decryptNativeRatchetMessage(ratchet, nativeEnvelope.encConnInfo);
    var conn = parseNativeAgentConnInfo(nativePlain.plaintext);
    if (conn.type !== 'info' && conn.type !== 'reply') fail('SIMPLEX_CONTACT_ACCEPT', 'native accept connection info is unsupported');
    if (decrypted.privateHeader.type === 'confirmation') {
      await this.client.secureQueue(queue, decrypted.privateHeader.senderPublicVerifyKey, {
        ...options,
        corrId: options.keyCorrId || options.corrId || ('native-accept-key-' + Date.now())
      });
    }
    var remoteProfile = {};
    try {
      remoteProfile = profileFromNativeConnInfo(conn.connInfo);
    } catch (_error) {
      remoteProfile = {};
    }
    contact.state = CONTACT_STATE_ACTIVE;
    contact.updatedAt = nowIso();
    contact.remoteProfile = remoteProfile;
    contact.inboundSenderPublicVerifyKey = decrypted.privateHeader.senderPublicVerifyKey || null;
    queue = {
      ...queue,
      e2eSharedSecret: inboundShared,
      nativeE2ePubDhKeySeen: true
    };
    this.store.saveQueue(contact.inboxQueueId || (contact.id + ':inbox'), queue);
    if (conn.type === 'reply') {
      var replyQueue = conn.replyQueues[0];
      if (!replyQueue) fail('SIMPLEX_CONTACT_ACCEPT', 'native accept reply queue is missing');
      var replySenderSignKey = generateEd25519KeyPair(options.replySenderSignSeed || options.senderSignSeed);
      contact.outboundQueue = {
        server: replyQueue.server,
        sndId: replyQueue.senderId,
        senderSignKey: replySenderSignKey,
        recipientDhPublicKey: replyQueue.dhPublicKey,
        smpClientVersion: replyQueue.smpClientVersion || replyQueue.clientVersion || 4,
        queueMode: replyQueue.queueMode,
        nativeReplyQueue: true
      };
      if (String(replyQueue.queueMode || '').toUpperCase() === 'M') {
        contact.outboundQueue = prepareNativeOutboundQueue(contact.outboundQueue, options);
        await this.client.secureSenderQueue(contact.outboundQueue, {
          ...options,
          corrId: options.skeyCorrId || options.corrId || ('native-reply-skey-' + Date.now())
        });
        var infoMessage = encodeNativeAgentConnInfo({
          type: 'info',
          connInfo: nativeProfileConnInfo(options.profile || contact.profile || {})
        });
        var infoHash = sha256Hash(infoMessage);
        var infoEncrypted = encryptNativeRatchetMessage(ratchet, infoMessage, {
          paddedLength: options.nativeEncConnInfoLength || options.encConnInfoLength || SIMPLEX_NATIVE_ENC_CONN_INFO_LENGTH,
          nextDhKey: options.nativeNextDhKey,
          ownDhKey: options.nativeOwnDhKey,
          ownDhSeed: options.nativeOwnDhSeed || options.ownDhSeed
        });
        ratchet = {
          nativeAgentProfile: true,
          nativeNextSndMsgId: 2,
          nativePrevMsgHash: infoHash,
          ...infoEncrypted.state
        };
        var infoAgentEnvelope = encodeNativeAgentEnvelope({
          type: 'confirmation',
          version: options.nativeAgentVersion || 7,
          encConnInfo: infoEncrypted.packet
        });
        var infoClientEnvelope = encodeNativeQueueClientMessage(contact.outboundQueue, infoAgentEnvelope, options);
        contact.outboundQueue = infoClientEnvelope.queue;
        await this.client.sendQueueMessage(contact.outboundQueue, infoClientEnvelope.body, {
          ...options,
          corrId: options.infoCorrId || options.confirmationCorrId || options.helloCorrId || options.corrId || ('native-reply-info-' + Date.now())
        });
      }
      this.store.saveQueue(outboxQueueId(contact), contact.outboundQueue);
    }
    this.store.saveContact(contact.id, contact);
    this.store.saveRatchet(contact.id, {
      nativeAgentProfile: true,
      ...ratchet
    });
    var ack = await this.acknowledgeOrQueue(contact, queue, received.message.msgId, {
      ...options,
      corrId: options.ackCorrId || options.corrId || ('native-accept-ack-' + Date.now())
    });
    return {
      contact,
      accept: { type: 'native-contact-accept', profile: remoteProfile },
      msgId: received.message.msgId,
      timestamp: decryptedBody.timestamp,
      ...ack
    };
  }

  activateContact(id, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    if (!contact) fail('SIMPLEX_CONTACT_MISSING', 'contact does not exist');
    var ratchet = createRatchetState({
      rootKey: options.rootKey,
      ownDhSeed: options.ownDhSeed,
      ownDhKey: options.ownDhKey,
      remoteDhPublicKey: options.remoteDhPublicKey,
      sendingChainKey: options.sendingChainKey,
      initializeSending: options.initializeSending
    });
    contact.state = CONTACT_STATE_ACTIVE;
    contact.updatedAt = nowIso();
    contact.outboundQueue = options.outboundQueue || contact.outboundQueue;
    this.store.saveContact(contact.id, contact);
    this.store.saveRatchet(contact.id, ratchet);
    if (contact.outboundQueue) this.store.saveQueue(contact.id + ':outbox', contact.outboundQueue);
    return contact;
  }

  suspendContact(id, reason = '') {
    var contact = this.store.loadContact(safeId(id));
    if (!contact) fail('SIMPLEX_CONTACT_MISSING', 'contact does not exist');
    contact.state = CONTACT_STATE_SUSPENDED;
    contact.reason = String(reason || '').slice(0, 500);
    contact.updatedAt = nowIso();
    this.store.saveContact(contact.id, contact);
    return contact;
  }

  deleteContact(id, options = {}) {
    var cleanId = safeId(id);
    var contact = this.store.loadContact(cleanId);
    var inboxQueueId = safeStoredId(contact && contact.inboxQueueId, cleanId + ':inbox');
    var outboxQueueId = safeStoredId(contact && contact.outboxQueueId, cleanId + ':outbox');
    if (typeof this.scheduler.removeWhere === 'function') {
      this.scheduler.removeWhere((task) => task && task.payload && task.payload.contactId === cleanId);
    }
    if (typeof this.store.deleteWhere === 'function') {
      this.store.deleteWhere('received', (value) => value && String(value.contactId || '') === cleanId, { deleteMalformed: true });
    } else if (typeof this.store.list === 'function' && typeof this.store.delete === 'function') {
      for (var row of this.store.list('received')) {
        if (row && row.value && String(row.value.contactId || '') === cleanId) {
          this.store.delete('received', row.id);
        }
      }
    }
    if (contact) {
      if (options.hardDelete === true) {
        this.store.deleteContact(cleanId);
      } else {
        this.store.saveContact(cleanId, {
          id: cleanId,
          state: CONTACT_STATE_DELETED,
          createdAt: contact.createdAt || nowIso(),
          updatedAt: nowIso(),
          deletedAt: nowIso()
        });
      }
    }
    this.store.deleteQueue(inboxQueueId);
    this.store.deleteQueue(outboxQueueId);
    this.store.deleteQueue(cleanId + ':inbox');
    this.store.deleteQueue(cleanId + ':outbox');
    if (typeof this.store.deleteRatchet === 'function') this.store.deleteRatchet(cleanId);
    return contact || null;
  }

  async deleteContactEverywhere(id, options = {}) {
    var cleanId = safeId(id);
    var contact = this.store.loadContact(cleanId);
    if (!contact) fail('SIMPLEX_CONTACT_MISSING', 'contact does not exist');
    var remoteDeletedQueues = [];
    var queueIds = ownedInboxQueueIds(contact, cleanId);
    for (var i = 0; i < queueIds.length; i += 1) {
      var queueId = queueIds[i];
      var queue = this.store.loadQueue(queueId);
      if (!queue) continue;
      // Broker-side deletion must happen before local scrubbing because the
      // DEL command needs the browser-owned recipient queue signing key.
      await this.client.deleteQueue(queue, deleteQueueOptions(options, queueId, i, this.client));
      remoteDeletedQueues.push(queueId);
    }
    if (!remoteDeletedQueues.length && options.requireRemoteQueue !== false) {
      fail('SIMPLEX_CONTACT_QUEUE', 'contact inbox queue is missing');
    }
    return {
      contact: this.deleteContact(cleanId, options),
      remoteDeletedQueues
    };
  }

  async sendText(id, text, options = {}) {
    var payloadText = encodeContactPayload({
      type: 'text',
      text: String(text == null ? '' : text),
      messageRef: optionalMessageRef(options.messageRef || options.clientMessageId || ''),
      createdAt: nowIso()
    });
    return this.sendPlaintext(id, utf8Bytes(payloadText), options);
  }

  async sendPlaintext(id, plaintext, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    requireState(contact, [CONTACT_STATE_ACTIVE]);
    var queue = options.queue || contact.outboundQueue || this.store.loadQueue(outboxQueueId(contact));
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'contact outbound queue is missing');
    var ratchet = this.store.loadRatchet(contact.id);
    if (!ratchet) fail('SIMPLEX_CONTACT_RATCHET', 'contact ratchet is missing');
    if (contact.nativeAgentProfile || ratchet.nativeAgentProfile) {
      var nativeSndMsgId = ratchet.nativeNextSndMsgId || 1;
      var nativePrevMsgHash = ratchet.nativePrevMsgHash || new Uint8Array();
      var nativeMessage = encodeNativeAgentMessage({
        type: 'message',
        sndMsgId: nativeSndMsgId,
        prevMsgHash: nativePrevMsgHash,
        body: encodeNativeChatBody(plaintext)
      });
      var nativeMsgHash = sha256Hash(nativeMessage);
      var nativeEncrypted = encryptNativeRatchetMessage(ratchet, nativeMessage, {
        paddedLength: options.nativePaddedLength || NATIVE_AGENT_MESSAGE_PADDED_LENGTH,
        nextDhKey: options.nativeNextDhKey,
        ownDhKey: options.nativeOwnDhKey,
        ownDhSeed: options.nativeOwnDhSeed || options.ownDhSeed
      });
      var nativeAgentEnvelope = encodeNativeAgentEnvelope({
        type: 'message',
        version: options.nativeAgentVersion || 7,
        encAgentMessage: nativeEncrypted.packet
      });
      var nativeClientEnvelope = encodeNativeQueueClientMessage(queue, nativeAgentEnvelope, options);
      queue = nativeClientEnvelope.queue;
      var nativeBody = nativeClientEnvelope.body;
      this.store.saveRatchet(contact.id, {
        nativeAgentProfile: true,
        nativeNextSndMsgId: nativeSndMsgId + 1,
        nativePrevMsgHash: nativeMsgHash,
        ...nativeEncrypted.state
      });
      if (!options.queue) {
        contact.outboundQueue = queue;
        this.store.saveContact(contact.id, contact);
        this.store.saveQueue(outboxQueueId(contact), queue);
      }
      var nativeTaskId = contact.id + ':send:' + (options.clientMessageId || Date.now());
      try {
        var nativeResponse = await this.client.sendQueueMessage(queue, nativeBody, options);
        this.scheduler.complete(nativeTaskId);
        return nativeResponse;
      } catch (error) {
        if (options.retryOnFailure !== false) {
          this.scheduler.enqueue(nativeTaskId, {
            type: 'sendPacket',
            contactId: contact.id,
            queueId: outboxQueueId(contact),
            packet: encodeBase64Url(nativeBody),
            options: { timeoutMs: options.timeoutMs || 0 }
          });
          this.scheduler.fail(nativeTaskId, error);
        }
        throw error;
      }
    }
    var encrypted = encryptRatchetMessage(ratchet, toBytes(plaintext, 'contact plaintext'), options);
    var body = packetBytes(encrypted.packet);
    this.store.saveRatchet(contact.id, encrypted.state);
    var taskId = contact.id + ':send:' + (options.clientMessageId || Date.now());
    try {
      var response = await this.client.sendQueueMessage(queue, body, options);
      this.scheduler.complete(taskId);
      return response;
    } catch (error) {
      if (options.retryOnFailure !== false) {
        // A failed send is retried as the same already-ratcheted packet. The
        // pending task does not need chat plaintext, so it stores only bytes
        // that were already safe to hand to the SMP transport.
        this.scheduler.enqueue(taskId, {
          type: 'sendPacket',
          contactId: contact.id,
          queueId: outboxQueueId(contact),
          packet: body,
          options: {
            clientMessageId: options.clientMessageId || '',
            timeoutMs: options.timeoutMs || 0,
            flags: options.flags || null
          }
        });
        this.scheduler.fail(taskId, error);
      }
      throw error;
    }
  }

  async sendFile(id, bytes, options = {}) {
    var xftp = requireXftpClient(options.xftpClient || this.xftpClient);
    var upload = await xftp.uploadFile(bytes, {
      name: options.name,
      mime: options.mime,
      chunkSize: options.chunkSize,
      fileId: options.fileId,
      rootKey: options.fileRootKey || options.xftpRootKey,
      profile: options.xftpProfile
    });
    var file = {
      manifest: upload.manifest,
      rootKey: encodeBase64Url(upload.rootKey),
      uploadedChunks: upload.uploadedChunks
    };
    var payloadText = encodeContactPayload({
      type: 'file',
      file,
      messageRef: optionalMessageRef(options.messageRef || options.clientMessageId || ''),
      createdAt: nowIso()
    });
    var response = await this.sendPlaintext(id, utf8Bytes(payloadText), options);
    return { ...response, file };
  }

  async sendReadReceipt(id, messageRef, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    var ratchet = contact ? this.store.loadRatchet(contact.id) : null;
    if (contact && (contact.nativeAgentProfile || (ratchet && ratchet.nativeAgentProfile)) && options.nativeAgentReceipt) {
      return this.sendNativeAgentReceipt(contact, {
        agentMsgId: normalizeNativeReceiptMessageId(options.nativeAgentMsgId || messageRef),
        msgHash: normalizeNativeReceiptHash(options.nativeMsgHash),
        rcptInfo: options.nativeReceiptInfo || utf8Bytes(String(options.readAt || options.read_at || nowIso()).slice(0, 64))
      }, options);
    }
    var payloadText = encodeContactPayload({
      type: 'read-receipt',
      messageRef: safeMessageRef(messageRef || options.messageRef || options.message_ref, 'read receipt message ref'),
      readAt: String(options.readAt || options.read_at || nowIso()).slice(0, 64)
    });
    return this.sendPlaintext(id, utf8Bytes(payloadText), options);
  }

  receiveText(id, packetBytesValue) {
    var contact = this.store.loadContact(safeId(id));
    requireState(contact, [CONTACT_STATE_ACTIVE]);
    var ratchet = this.store.loadRatchet(contact.id);
    if (!ratchet) fail('SIMPLEX_CONTACT_RATCHET', 'contact ratchet is missing');
    var decrypted = decryptRatchetMessage(ratchet, parsePacketBytes(toBytes(packetBytesValue, 'ratchet packet')));
    this.store.saveRatchet(contact.id, decrypted.state);
    return utf8Text(decrypted.plaintext);
  }

  async acknowledgeOrQueue(contact, queue, msgId, options = {}) {
    if (options.acknowledge === false) {
      return { acknowledged: false, ackPending: false, ackError: '' };
    }
    try {
      await this.client.acknowledgeMessage(queue, msgId, {
        ...options,
        corrId: options.ackCorrId || options.corrId || ('ack-' + Date.now())
      });
      return { acknowledged: true, ackPending: false, ackError: '' };
    } catch (error) {
      if (options.retryAckOnFailure === false) throw error;
      var taskId = ackTaskId(contact.id, msgId);
      this.scheduler.enqueue(taskId, {
        type: 'ackMessage',
        contactId: contact.id,
        queueId: contact.inboxQueueId || (contact.id + ':inbox'),
        msgId: encodeBase64Url(msgId),
        options: { timeoutMs: options.timeoutMs || 0 }
      });
      this.scheduler.fail(taskId, error);
      return {
        acknowledged: false,
        ackPending: true,
        ackError: String(error && error.message || error || '').slice(0, 500)
      };
    }
  }

  async sendNativeAgentReceipt(contact, receipt, options = {}) {
    requireState(contact, [CONTACT_STATE_ACTIVE]);
    var queue = options.queue || contact.outboundQueue || this.store.loadQueue(outboxQueueId(contact));
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'native receipt outbound queue is missing');
    var ratchet = this.store.loadRatchet(contact.id);
    if (!ratchet || !ratchet.nativeAgentProfile) fail('SIMPLEX_CONTACT_RATCHET', 'native receipt ratchet is missing');
    var normalizedReceipt = {
      agentMsgId: normalizeNativeReceiptMessageId(receipt.agentMsgId || receipt.id),
      msgHash: normalizeNativeReceiptHash(receipt.msgHash || receipt.hash),
      rcptInfo: receipt.rcptInfo || receipt.info || new Uint8Array()
    };
    var nativeSndMsgId = ratchet.nativeNextSndMsgId || 1;
    var nativeReceipt = encodeNativeAgentMessage({
      type: 'receipt',
      sndMsgId: nativeSndMsgId,
      prevMsgHash: ratchet.nativePrevMsgHash || new Uint8Array(),
      receipts: [normalizedReceipt]
    });
    var nativeMsgHash = sha256Hash(nativeReceipt);
    var nativeEncrypted = encryptNativeRatchetMessage(ratchet, nativeReceipt, {
      paddedLength: options.nativePaddedLength || NATIVE_AGENT_MESSAGE_PADDED_LENGTH,
      nextDhKey: options.nativeNextDhKey,
      ownDhKey: options.nativeOwnDhKey,
      ownDhSeed: options.nativeOwnDhSeed || options.ownDhSeed
    });
    var nativeAgentEnvelope = encodeNativeAgentEnvelope({
      type: 'message',
      version: options.nativeAgentVersion || 7,
      encAgentMessage: nativeEncrypted.packet
    });
    var nativeClientEnvelope = encodeNativeQueueClientMessage(queue, nativeAgentEnvelope, options);
    queue = nativeClientEnvelope.queue;
    this.store.saveRatchet(contact.id, {
      nativeAgentProfile: true,
      nativeNextSndMsgId: nativeSndMsgId + 1,
      nativePrevMsgHash: nativeMsgHash,
      ...nativeEncrypted.state
    });
    if (!options.queue) {
      contact.outboundQueue = queue;
      this.store.saveContact(contact.id, contact);
      this.store.saveQueue(outboxQueueId(contact), queue);
    }
    var nativeBody = nativeClientEnvelope.body;
    var receiptTaskId = contact.id + ':receipt:' + String(options.clientMessageId || normalizedReceipt.agentMsgId || Date.now());
    try {
      var response = await this.client.sendQueueMessage(queue, nativeBody, {
        ...options,
        corrId: options.receiptCorrId || options.corrId || ('native-receipt-' + Date.now())
      });
      this.scheduler.complete(receiptTaskId);
      return response;
    } catch (error) {
      if (options.retryOnFailure !== false) {
        this.scheduler.enqueue(receiptTaskId, {
          type: 'sendPacket',
          contactId: contact.id,
          queueId: outboxQueueId(contact),
          packet: encodeBase64Url(nativeBody),
          options: { timeoutMs: options.timeoutMs || 0 }
        });
        this.scheduler.fail(receiptTaskId, error);
      }
      throw error;
    }
  }

  async receiveNext(id, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    requireState(contact, [CONTACT_STATE_ACTIVE]);
    var queue = options.queue || this.store.loadQueue(contact.id + ':inbox');
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'contact inbox queue is missing');
    var received = await this.client.receiveQueueMessage(queue, options);
    var msgId = received.message.msgId;
    var bodyHash = receivedBodyHash(received.message.body);
    var seenId = receivedRecordId(contact.id, msgId);
    var seen = this.store.load('received', seenId);
    if (seen) {
      if (seen.bodyHash && seen.bodyHash !== bodyHash) {
        fail('SIMPLEX_CONTACT_REPLAY', 'received message id replay changed the encrypted body');
      }
      var duplicateAck = await this.acknowledgeOrQueue(contact, queue, msgId, options);
      this.store.save('received', seenId, {
        ...seen,
        duplicateSeenAt: nowIso(),
        ackPending: duplicateAck.ackPending,
        ackError: duplicateAck.ackError,
        acknowledgedAt: duplicateAck.acknowledged ? nowIso() : seen.acknowledgedAt || ''
      });
      return {
        contactId: contact.id,
        text: '',
        payload: { type: 'duplicate' },
        file: null,
        msgId,
        timestamp: seen.timestamp || 0n,
        flags: seen.flags || {},
        duplicate: true,
        ...duplicateAck
      };
    }
    var decryptedBody = decryptRcvMessageBody({
      serverDhSecret: queue.serverDhSecret,
      msgId,
      encryptedBody: received.message.body
    });
    var ratchet = this.store.loadRatchet(contact.id);
    if (!ratchet) fail('SIMPLEX_CONTACT_RATCHET', 'contact ratchet is missing');
    if (contact.nativeAgentProfile || ratchet.nativeAgentProfile) {
      var nativeEnvelopeBody = decryptedBody.body;
      if (queue.e2eSharedSecret) {
        var nativeClientMessage = decryptClientMessageEnvelope({
          sharedSecret: queue.e2eSharedSecret,
          envelope: decryptedBody.body
        });
        if (nativeClientMessage.privateHeader.type !== 'empty') {
          fail('SIMPLEX_CONTACT_MESSAGE', 'native incoming message has an unsupported private header');
        }
        nativeEnvelopeBody = nativeClientMessage.body;
      }
      var nativeEnvelope = parseNativeAgentEnvelope(nativeEnvelopeBody);
      if (nativeEnvelope.type !== 'message') fail('SIMPLEX_CONTACT_MESSAGE', 'native incoming envelope must be a message');
      var nativeDecrypted = decryptNativeRatchetMessage(ratchet, nativeEnvelope.encAgentMessage);
      var nativeAgentMessage = parseNativeAgentMessage(nativeDecrypted.plaintext);
      if (nativeAgentMessage.type === 'receipt') {
        this.store.saveRatchet(contact.id, {
          nativeAgentProfile: true,
          ...nativeDecrypted.state
        });
        this.store.save('received', seenId, {
          contactId: contact.id,
          queueId: contact.inboxQueueId || (contact.id + ':inbox'),
          msgId: encodeBase64Url(msgId),
          bodyHash,
          timestamp: decryptedBody.timestamp,
          flags: decryptedBody.flags,
          payloadType: 'read-receipt',
          receivedAt: nowIso(),
          nativeReceiptCount: nativeAgentMessage.receipts.length
        });
        var nativeReceiptAck = await this.acknowledgeOrQueue(contact, queue, msgId, options);
        this.store.save('received', seenId, {
          ...(this.store.load('received', seenId) || {}),
          ackPending: nativeReceiptAck.ackPending,
          ackError: nativeReceiptAck.ackError,
          acknowledgedAt: nativeReceiptAck.acknowledged ? nowIso() : ''
        });
        return {
          contactId: contact.id,
          text: '',
          payload: {
            type: 'read-receipt',
            receipts: nativeAgentMessage.receipts.map((item) => ({
              agentMsgId: String(item.agentMsgId),
              msgHash: encodeBase64Url(item.msgHash),
              rcptInfo: encodeBase64Url(item.rcptInfo)
            }))
          },
          file: null,
          msgId,
          timestamp: decryptedBody.timestamp,
          flags: decryptedBody.flags,
          duplicate: false,
          ...nativeReceiptAck
        };
      }
      if (nativeAgentMessage.type !== 'message') fail('SIMPLEX_CONTACT_MESSAGE', 'native incoming agent message type is unsupported');
      var nativeChat = decodeNativeChatBody(nativeAgentMessage.body);
      var nativeText = nativeChat.text;
      var nativePayload = nativeChat.payload;
      this.store.saveRatchet(contact.id, {
        nativeAgentProfile: true,
        ...nativeDecrypted.state
      });
      this.store.save('received', seenId, {
        contactId: contact.id,
        queueId: contact.inboxQueueId || (contact.id + ':inbox'),
        msgId: encodeBase64Url(msgId),
        bodyHash,
        timestamp: decryptedBody.timestamp,
        flags: decryptedBody.flags,
        payloadType: nativePayload.type || 'text',
        receivedAt: nowIso()
      });
      var nativeAck = await this.acknowledgeOrQueue(contact, queue, msgId, options);
      var nativeReceipt = null;
      var nativeReceiptError = '';
      if (options.sendNativeReceipts !== false && nativeAgentMessage.sndMsgId != null) {
        try {
          nativeReceipt = await this.sendNativeAgentReceipt(contact, {
            agentMsgId: nativeAgentMessage.sndMsgId,
            msgHash: sha256Hash(nativeDecrypted.plaintext),
            rcptInfo: options.nativeReceiptInfo || new Uint8Array()
          }, {
            ...options,
            queue: options.receiptQueue,
            corrId: options.receiptCorrId || ('native-receipt-' + Date.now())
          });
        } catch (error) {
          nativeReceiptError = String(error && error.message || error || '').slice(0, 500);
        }
      }
      this.store.save('received', seenId, {
        ...(this.store.load('received', seenId) || {}),
        ackPending: nativeAck.ackPending,
        ackError: nativeAck.ackError,
        nativeReceiptPending: !!nativeReceiptError,
        nativeReceiptError,
        acknowledgedAt: nativeAck.acknowledged ? nowIso() : ''
      });
      return {
        contactId: contact.id,
        text: nativePayload.type === 'text' ? nativePayload.text : nativeText,
        payload: nativePayload,
        file: nativePayload.type === 'file' ? nativePayload.file : null,
        msgId,
        timestamp: decryptedBody.timestamp,
        flags: decryptedBody.flags,
        duplicate: false,
        nativeReceipt,
        nativeReceiptError,
        ...nativeAck
      };
    }
    var decryptedPacket = decryptRatchetMessage(ratchet, parsePacketBytes(decryptedBody.body));
    var text = utf8Text(decryptedPacket.plaintext);
    var payload = decodeContactPayload(text);
    // Persist the ratchet only after the higher-level payload is validated. A
    // malformed prefixed payload must not consume a message key before the
    // broker message can be retried or handled manually.
    this.store.saveRatchet(contact.id, decryptedPacket.state);
    // Store only metadata and encrypted-body fingerprints before the ACK. If a
    // server redelivers the same message because ACK failed, the caller will not
    // receive the plaintext twice and the ratchet will not be replayed.
    this.store.save('received', seenId, {
      contactId: contact.id,
      queueId: contact.inboxQueueId || (contact.id + ':inbox'),
      msgId: encodeBase64Url(msgId),
      bodyHash,
      timestamp: decryptedBody.timestamp,
      flags: decryptedBody.flags,
      payloadType: payload.type || 'text',
      receivedAt: nowIso()
    });
    var ack = await this.acknowledgeOrQueue(contact, queue, msgId, options);
    this.store.save('received', seenId, {
      ...(this.store.load('received', seenId) || {}),
      ackPending: ack.ackPending,
      ackError: ack.ackError,
      acknowledgedAt: ack.acknowledged ? nowIso() : ''
    });
    return {
      contactId: contact.id,
      text: payload.type === 'text' ? payload.text : '',
      payload,
      file: payload.type === 'file' ? payload.file : null,
      msgId,
      timestamp: decryptedBody.timestamp,
      flags: decryptedBody.flags,
      duplicate: false,
      ...ack
    };
  }

  async downloadReceivedFile(received, options = {}) {
    var xftp = requireXftpClient(options.xftpClient || this.xftpClient);
    var file = received && received.file ? received.file : null;
    if (!file || !file.manifest || !file.rootKey) fail('SIMPLEX_CONTACT_FILE', 'received file payload is missing');
    return xftp.downloadFile(file.manifest, decodeBase64Url(file.rootKey, 'received file root key'), options);
  }

  async drainDueRetries(options = {}) {
    var due = this.scheduler.due(options.now).slice(0, Math.max(1, Math.floor(Number(options.limit || 25) || 25)));
    var results = [];
    for (var task of due) {
      if (!task || !task.payload) continue;
      if (task.payload.type !== 'sendPacket' && task.payload.type !== 'ackMessage' && task.payload.type !== 'initialConfirmation') continue;
      try {
        var response;
        if (task.payload.type === 'sendPacket') {
          var sendPacketOptions = {
            ...(task.payload.options || {}),
            ...(options.sendOptions || {}),
            retryOnFailure: false
          };
          var sendContact = this.store.loadContact(safeId(task.payload.contactId));
          if (!sendContact) fail('SIMPLEX_CONTACT_MISSING', 'contact does not exist');
          var sendQueue = options.queue || sendContact.outboundQueue || this.store.loadQueue(task.payload.queueId || outboxQueueId(sendContact));
          if (!sendQueue) fail('SIMPLEX_CONTACT_QUEUE', 'contact retry queue is missing');
          response = await this.client.sendQueueMessage(sendQueue, retryBytes(task.payload.packet, 'retry packet'), sendPacketOptions);
        } else if (task.payload.type === 'initialConfirmation') {
          response = await this.client.sendPreparedTransmission(
            retryBytes(task.payload.transmission, 'retry initial confirmation transmission'),
            retryBytes(task.payload.corrId, 'retry initial confirmation correlation id'),
            {
              ...(task.payload.options || {}),
              ...(options.initialOptions || {})
            }
          );
        } else {
          // ACK retry tasks carry only enough metadata to repeat the SMP ACK.
          // They deliberately avoid storing the plaintext message or ratchet
          // packet because the website already received and decrypted it.
          var contact = this.store.loadContact(safeId(task.payload.contactId));
          if (!contact) fail('SIMPLEX_CONTACT_MISSING', 'contact does not exist');
          var queue = this.store.loadQueue(task.payload.queueId || contact.inboxQueueId || (contact.id + ':inbox'));
          if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'contact ACK queue is missing');
          response = await this.client.acknowledgeMessage(queue, decodeBase64Url(task.payload.msgId, 'retry ACK msg id'), {
            ...(task.payload.options || {}),
            ...(options.ackOptions || {}),
            corrId: (options.ackOptions && (options.ackOptions.corrId || options.ackOptions.ackCorrId)) || this.client.makeCorrId('ack')
          });
        }
        this.scheduler.complete(task.id);
        results.push({ id: task.id, ok: true, response });
      } catch (error) {
        this.scheduler.fail(task.id, error);
        results.push({ id: task.id, ok: false, error });
      }
    }
    return results;
  }

  listContacts() {
    return this.store.listContacts().map((row) => row.value);
  }
}

export default {
  BrowserSimplexContactClient,
  BrowserSimplexContactError,
  CONTACT_PAYLOAD_PREFIX,
  CONTACT_STATE_ACTIVE,
  CONTACT_STATE_DELETED,
  CONTACT_STATE_INVITED,
  CONTACT_STATE_REQUESTED,
  CONTACT_STATE_SUSPENDED,
  decodeContactPayload,
  encodeContactPayload,
  createBrowserSimplexContactClient
};
