// SPDX-License-Identifier: AGPL-3.0-only
//
// Small browser-native SimpleX client orchestrator.
//
// This module wires the low-level SMP core, agent-envelope helpers, and an
// abstract SMP transport together.  It intentionally stays low to the ground:
// callers provide a transport with `sendSignedTransmissions()` and
// `receiveSignedTransmissions()`, and this module performs queue-level protocol
// steps without owning UI, storage, sockets, or compatibility command shims.

import {
  asciiBytes,
  asciiText,
  equalBytes,
  toBytes
} from './browser-smp-core.mjs';
import {
  completeNewQueueRequest,
  prepareInitialSenderMessage,
  prepareNewQueueRequest,
  prepareRecipientCommand,
  prepareSenderMessage,
  queueSummary
} from './browser-simplex-agent.mjs';

export class BrowserSimplexClientError extends Error {
  constructor(code, message, detail = null) {
    super(message);
    this.name = 'BrowserSimplexClientError';
    this.code = code;
    this.detail = detail;
  }
}

function fail(code, message, detail) {
  throw new BrowserSimplexClientError(code, message, detail);
}

function requireTransport(transport) {
  if (!transport || typeof transport.sendSignedTransmissions !== 'function' || typeof transport.receiveSignedTransmissions !== 'function') {
    fail('SIMPLEX_CLIENT_TRANSPORT', 'browser SimpleX client requires an SMP transport');
  }
  return transport;
}

function normalizeCorrId(value, fallback) {
  var corr = value == null ? fallback : value;
  var bytes = typeof corr === 'string' ? asciiBytes(corr) : toBytes(corr, 'correlation id');
  if (!bytes.length || bytes.length > 32) fail('SIMPLEX_CLIENT_CORR_ID', 'correlation id must be 1 to 32 bytes');
  for (var i = 0; i < bytes.length; i += 1) {
    if (bytes[i] <= 0x20 || bytes[i] > 0x7e) fail('SIMPLEX_CLIENT_CORR_ID', 'correlation id must be printable non-space ASCII');
  }
  return bytes;
}

function brokerType(transmission) {
  return String(transmission && (transmission.message && transmission.message.type || transmission.type || '')).toUpperCase();
}

function brokerMessage(transmission) {
  return transmission && transmission.message ? transmission.message : transmission;
}

function errorText(message) {
  var err = message && message.error;
  if (!err) return 'SMP server returned an error';
  if (typeof err === 'string') return err;
  if (err.type === 'CMD') return 'CMD ' + String(err.commandError || 'SYNTAX');
  return String(err.type || 'SMP server error');
}

function queueMatches(transmission, queue) {
  if (!queue || !queue.rcvId || !transmission || !transmission.queueId) return true;
  return equalBytes(transmission.queueId, queue.rcvId);
}

export function createBrowserSimplexClient(options = {}) {
  return new BrowserSimplexClient(options);
}

export class BrowserSimplexClient {
  constructor(options = {}) {
    this.transport = requireTransport(options.transport);
    this.server = options.server || null;
    this.version = options.version || this.transport.version || 4;
    this.sessionId = options.sessionId || this.transport.sessionId || new Uint8Array();
    this.nextId = 1;
    this.queues = new Map();
    this.pendingTransmissions = [];
    this.maxPendingTransmissions = Math.max(16, Math.floor(Number(options.maxPendingTransmissions || 512) || 512));
  }

  makeCorrId(prefix = 'c') {
    var safePrefix = String(prefix || 'c').replace(/[^A-Za-z0-9_.:-]/g, '').slice(0, 12) || 'c';
    return asciiBytes(safePrefix + '-' + this.nextId++);
  }

  rememberQueue(label, queue) {
    var key = String(label || asciiText(queue.rcvId || this.makeCorrId('q')));
    this.queues.set(key, queue);
    return queue;
  }

  getQueue(label) {
    var queue = this.queues.get(String(label || ''));
    if (!queue) fail('SIMPLEX_CLIENT_QUEUE', 'queue is not known');
    return queue;
  }

  rememberPending(transmission) {
    if (!transmission) return;
    this.pendingTransmissions.push(transmission);
    if (this.pendingTransmissions.length > this.maxPendingTransmissions) {
      this.pendingTransmissions.splice(0, this.pendingTransmissions.length - this.maxPendingTransmissions);
    }
  }

  takePending(predicate) {
    for (var i = 0; i < this.pendingTransmissions.length; i += 1) {
      if (predicate(this.pendingTransmissions[i])) {
        return this.pendingTransmissions.splice(i, 1)[0];
      }
    }
    return null;
  }

  async sendAndWait(transmission, corrId, options = {}) {
    this.transport.sendSignedTransmissions([transmission]);
    return this.receiveForCorr(corrId, options);
  }

  async receiveForCorr(corrId, options = {}) {
    var expected = toBytes(corrId, 'correlation id');
    var maxBatches = Math.max(1, Math.floor(Number(options.maxBatches || 25) || 25));
    var pending = this.takePending((tx) => tx && tx.corrId && equalBytes(tx.corrId, expected));
    if (pending) {
      if (brokerType(pending) === 'ERR') fail('SIMPLEX_CLIENT_BROKER_ERR', errorText(brokerMessage(pending)), brokerMessage(pending));
      return pending;
    }
    for (var i = 0; i < maxBatches; i += 1) {
      var transmissions = await this.transport.receiveSignedTransmissions({
        kind: 'broker',
        timeoutMs: options.timeoutMs
      });
      for (var tx of transmissions || []) {
        if (!tx || !tx.corrId) continue;
        if (equalBytes(tx.corrId, expected)) {
          var message = brokerMessage(tx);
          if (brokerType(tx) === 'ERR') {
            fail('SIMPLEX_CLIENT_BROKER_ERR', errorText(message), message);
          }
          return tx;
        }
        this.rememberPending(tx);
      }
    }
    fail('SIMPLEX_CLIENT_TIMEOUT', 'no SMP response matched the correlation id');
  }

  async receiveQueueMessage(queueOrLabel, options = {}) {
    var queue = typeof queueOrLabel === 'string' ? this.getQueue(queueOrLabel) : queueOrLabel;
    var maxBatches = Math.max(1, Math.floor(Number(options.maxBatches || 25) || 25));
    var pending = this.takePending((tx) => brokerType(tx) === 'MSG' && queueMatches(tx, queue));
    if (pending) return { queue, transmission: pending, message: brokerMessage(pending) };
    for (var i = 0; i < maxBatches; i += 1) {
      var transmissions = await this.transport.receiveSignedTransmissions({
        kind: 'broker',
        timeoutMs: options.timeoutMs
      });
      for (var tx of transmissions || []) {
        var message = brokerMessage(tx);
        var type = brokerType(tx);
        if (type === 'ERR') fail('SIMPLEX_CLIENT_BROKER_ERR', errorText(message), message);
        if (type === 'MSG' && queueMatches(tx, queue)) {
          return { queue, transmission: tx, message };
        }
        this.rememberPending(tx);
      }
    }
    fail('SIMPLEX_CLIENT_TIMEOUT', 'no SMP message matched the queue');
  }

  async createQueue(options = {}) {
    var corrId = normalizeCorrId(options.corrId, this.makeCorrId('new'));
    var pending = prepareNewQueueRequest({
      version: this.version,
      sessionId: this.sessionId,
      corrId,
      server: options.server || this.server,
      rcvSignSeed: options.rcvSignSeed,
      rcvDhSeed: options.rcvDhSeed,
      transportBlock: false
    });
    var response = await this.sendAndWait(pending.transmission, corrId, options);
    if (brokerType(response) !== 'IDS') fail('SIMPLEX_CLIENT_PROTOCOL', 'NEW expected IDS response', response);
    var queue = completeNewQueueRequest(pending, brokerMessage(response), {
      version: this.version,
      server: options.server || this.server
    });
    this.rememberQueue(options.label || asciiText(corrId), queue);
    return queue;
  }

  async recipientCommand(queueOrLabel, command, options = {}) {
    var queue = typeof queueOrLabel === 'string' ? this.getQueue(queueOrLabel) : queueOrLabel;
    var corrId = normalizeCorrId(options.corrId, this.makeCorrId(String(command && command.type || 'cmd').toLowerCase()));
    var transmission = prepareRecipientCommand(queue, {
      version: this.version,
      sessionId: this.sessionId,
      corrId,
      command
    });
    return this.sendAndWait(transmission, corrId, options);
  }

  subscribeQueue(queueOrLabel, options = {}) {
    return this.recipientCommand(queueOrLabel, { type: 'SUB' }, options);
  }

  acknowledgeMessage(queueOrLabel, msgId, options = {}) {
    return this.recipientCommand(queueOrLabel, { type: 'ACK', msgId }, options);
  }

  secureQueue(queueOrLabel, senderPublicVerifyKey, options = {}) {
    return this.recipientCommand(queueOrLabel, {
      type: 'KEY',
      sndPublicVerifyKey: senderPublicVerifyKey
    }, options);
  }

  deleteQueue(queueOrLabel, options = {}) {
    return this.recipientCommand(queueOrLabel, { type: 'DEL' }, options);
  }

  async sendInitialConfirmation(options = {}) {
    var corrId = normalizeCorrId(options.corrId, this.makeCorrId('confirm'));
    var prepared = prepareInitialSenderMessage({
      version: this.version,
      sessionId: this.sessionId,
      corrId,
      senderQueueId: options.senderQueueId,
      senderSignKey: options.senderSignKey,
      senderSignSeed: options.senderSignSeed,
      e2eSharedSecret: options.e2eSharedSecret,
      senderE2ePubDhKey: options.senderE2ePubDhKey,
      nonce: options.nonce,
      body: options.body,
      flags: options.flags
    });
    var response = await this.sendAndWait(prepared.transmission, corrId, options);
    if (brokerType(response) !== 'OK') fail('SIMPLEX_CLIENT_PROTOCOL', 'initial confirmation expected OK response', response);
    return {
      senderSignKey: prepared.senderSignKey,
      response
    };
  }

  async sendQueueMessage(queueOrLabel, body, options = {}) {
    var queue = typeof queueOrLabel === 'string' ? this.getQueue(queueOrLabel) : queueOrLabel;
    var corrId = normalizeCorrId(options.corrId, this.makeCorrId('send'));
    var transmission = prepareSenderMessage(queue, {
      version: this.version,
      sessionId: this.sessionId,
      corrId,
      body,
      flags: options.flags || { notification: false }
    });
    var response = await this.sendAndWait(transmission, corrId, options);
    if (brokerType(response) !== 'OK') fail('SIMPLEX_CLIENT_PROTOCOL', 'SEND expected OK response', response);
    return response;
  }

  status() {
    return {
      version: this.version,
      queueCount: this.queues.size,
      pendingTransmissionCount: this.pendingTransmissions.length,
      transport: typeof this.transport.getStatus === 'function' ? this.transport.getStatus() : null,
      queues: Array.from(this.queues.entries()).map(([label, queue]) => ({
        label,
        summary: queueSummary(queue)
      }))
    };
  }
}

export default {
  BrowserSimplexClient,
  BrowserSimplexClientError,
  createBrowserSimplexClient
};
