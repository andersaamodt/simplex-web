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
  formatSmpQueueUri,
  generateX25519KeyPair,
  parseSmpQueueUri,
  sha256Hash,
  toBytes,
  utf8Bytes,
  utf8Text,
  x25519SharedSecret
} from './browser-smp-core.mjs';
import { createBrowserSimplexClient } from './browser-simplex-client.mjs';
import { createBrowserSimplexStore } from './browser-simplex-store.mjs';
import { createBrowserSimplexRetryScheduler } from './browser-simplex-scheduler.mjs';
import { decryptClientMessageEnvelope, decryptRcvMessageBody, parseClientMessageEnvelope } from './browser-simplex-agent.mjs';
import { createRatchetState, decryptRatchetMessage, encryptRatchetMessage } from './browser-simplex-ratchet.mjs';
import { createBrowserXftpClient } from './browser-xftp-client.mjs';

export const CONTACT_STATE_INVITED = 'invited';
export const CONTACT_STATE_REQUESTED = 'requested';
export const CONTACT_STATE_ACTIVE = 'active';
export const CONTACT_STATE_SUSPENDED = 'suspended';
export const CONTACT_STATE_DELETED = 'deleted';
export const CONTACT_PAYLOAD_PREFIX = 'simplex-web:payload:v1\n';

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
  if (parsed.type !== 'file') fail('SIMPLEX_CONTACT_PAYLOAD', 'contact payload type is unsupported');
  if (!parsed.file || typeof parsed.file !== 'object') fail('SIMPLEX_CONTACT_PAYLOAD', 'contact file payload is invalid');
  return parsed;
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

function ackTaskId(contactId, msgId) {
  return 'ack:' + encodeBase64Url(msgId).slice(0, 96) + ':' + encodeBase64Url(utf8Bytes(safeId(contactId))).slice(0, 48);
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

function outboxQueueId(contact) {
  return contact.outboxQueueId || (contact.id + ':outbox');
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
    var parsed = parseSmpQueueUri(invitationUri);
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
    var confirmation = await this.client.sendInitialConfirmation({
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
        senderSignKey: confirmation.senderSignKey
      }
    };
    this.store.saveContact(cleanId, contact);
    this.store.saveQueue(cleanId + ':outbox', contact.outboundQueue);
    this.store.saveRatchet(cleanId, createRatchetState({
      rootKey: shared,
      ownDhKey,
      remoteDhPublicKey: recipientDh.rawPublicKey
    }));
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
    if (options.acknowledge !== false) {
      await this.client.acknowledgeMessage(queue, received.message.msgId, {
        ...options,
        corrId: options.ackCorrId || ('ack-' + Date.now())
      });
    }
    contact.state = CONTACT_STATE_ACTIVE;
    contact.updatedAt = nowIso();
    contact.remoteProfile = request.profile || {};
    contact.inboundSenderPublicVerifyKey = decrypted.privateHeader.senderPublicVerifyKey;
    var accept = null;
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
      accept = await this.client.sendInitialConfirmation({
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
        senderSignKey: accept.senderSignKey
      };
      contact.outboxQueueId = contact.id + ':outbox';
      this.store.saveQueue(contact.outboxQueueId, contact.outboundQueue);
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
    return {
      contact,
      request,
      accept,
      msgId: received.message.msgId,
      timestamp: decryptedBody.timestamp
    };
  }

  async receiveContactAccept(id, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    requireState(contact, [CONTACT_STATE_REQUESTED, CONTACT_STATE_ACTIVE]);
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
    if (options.acknowledge !== false) {
      await this.client.acknowledgeMessage(queue, received.message.msgId, {
        ...options,
        corrId: options.ackCorrId || ('accept-ack-' + Date.now())
      });
    }
    contact.state = CONTACT_STATE_ACTIVE;
    contact.updatedAt = nowIso();
    contact.remoteProfile = accept.profile || {};
    contact.inboundSenderPublicVerifyKey = decrypted.privateHeader.senderPublicVerifyKey;
    this.store.saveContact(contact.id, contact);
    return {
      contact,
      accept,
      msgId: received.message.msgId,
      timestamp: decryptedBody.timestamp
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
    if (typeof this.store.list === 'function' && typeof this.store.delete === 'function') {
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

  async sendText(id, text, options = {}) {
    return this.sendPlaintext(id, utf8Bytes(text), options);
  }

  async sendPlaintext(id, plaintext, options = {}) {
    var contact = this.store.loadContact(safeId(id));
    requireState(contact, [CONTACT_STATE_ACTIVE]);
    var ratchet = this.store.loadRatchet(contact.id);
    if (!ratchet) fail('SIMPLEX_CONTACT_RATCHET', 'contact ratchet is missing');
    var encrypted = encryptRatchetMessage(ratchet, toBytes(plaintext, 'contact plaintext'), options);
    var body = packetBytes(encrypted.packet);
    this.store.saveRatchet(contact.id, encrypted.state);
    var queue = options.queue || contact.outboundQueue || this.store.loadQueue(outboxQueueId(contact));
    if (!queue) fail('SIMPLEX_CONTACT_QUEUE', 'contact outbound queue is missing');
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
          packet: encodeBase64Url(body),
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
    var payloadText = encodeContactPayload({ type: 'file', file });
    var response = await this.sendPlaintext(id, utf8Bytes(payloadText), options);
    return { ...response, file };
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
    var text = this.receiveText(contact.id, decryptedBody.body);
    var payload = decodeContactPayload(text);
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
      if (task.payload.type !== 'sendPacket' && task.payload.type !== 'ackMessage') continue;
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
          response = await this.client.sendQueueMessage(sendQueue, decodeBase64Url(task.payload.packet, 'retry packet'), sendPacketOptions);
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
