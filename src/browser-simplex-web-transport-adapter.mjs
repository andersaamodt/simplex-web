// SPDX-License-Identifier: AGPL-3.0-only
//
// First-party adapter for `window.SimplexWebTransport`.
//
// The public facade in `src/transport.js` is intentionally stable and small:
// websites call `sendText`, `sendFiles`, `getMessages`, and `connect`.
// This module supplies the real browser-native adapter behind that facade. It
// wires the binary SMP-over-WebSocket profile, durable browser store, contact
// client, and optional XFTP web file client together without introducing a
// plaintext server bridge.

import {
  decodeBase64Url,
  encodeBase64Url,
  hexToBytes,
  toBytes
} from './browser-smp-core.mjs';
import { createBrowserSimplexClient } from './browser-simplex-client.mjs';
import { createBrowserSimplexContactClient } from './browser-simplex-contact-client.mjs';
import { createBrowserSimplexStore } from './browser-simplex-store.mjs';
import { connectBrowserSmpWebSocketTransport } from './browser-smp-websocket-transport.mjs';
import {
  connectBrowserXftpWebClient,
  downloadXftpWebFile,
  uploadXftpWebFile
} from './browser-xftp-web-client.mjs';

const MAX_CONTACT_ID_LENGTH = 160;
const DEFAULT_RECEIVE_LIMIT = 25;

export class SimplexWebTransportAdapterError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SimplexWebTransportAdapterError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new SimplexWebTransportAdapterError(code, message);
}

function safeContactId(value) {
  var id = String(value == null ? '' : value).trim();
  if (!id || id.length > MAX_CONTACT_ID_LENGTH || /[^A-Za-z0-9_.:-]/.test(id)) {
    fail('SIMPLEX_WEB_ADAPTER_CONTACT', 'contact id is required and must be filename-safe ASCII');
  }
  return id;
}

function safeText(value) {
  var text = String(value == null ? '' : value);
  if (!text.trim()) fail('SIMPLEX_WEB_ADAPTER_TEXT', 'message text is required');
  return text;
}

function decodeConfigBytes(value, label) {
  if (value == null || value === '') return new Uint8Array();
  if (value instanceof Uint8Array || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return toBytes(value, label);
  var text = String(value).trim();
  if (/^[0-9a-f]+$/i.test(text) && text.length % 2 === 0) return hexToBytes(text);
  return decodeBase64Url(text, label);
}

function generatedMessageRef(prefix) {
  var random = Math.random().toString(36).slice(2);
  return prefix + '-' + Date.now().toString(36) + '-' + random;
}

async function readFileBytes(file, maxBytes) {
  if (file instanceof Uint8Array || file instanceof ArrayBuffer || ArrayBuffer.isView(file)) {
    var bytes = toBytes(file, 'file bytes');
    if (bytes.length > maxBytes) fail('SIMPLEX_WEB_ADAPTER_FILE_SIZE', 'file is larger than the configured maximum');
    return bytes;
  }
  if (!file || typeof file !== 'object') fail('SIMPLEX_WEB_ADAPTER_FILE', 'file object is required');
  var size = Number(file.size || 0);
  if (Number.isFinite(size) && size > maxBytes) fail('SIMPLEX_WEB_ADAPTER_FILE_SIZE', 'file is larger than the configured maximum');
  if (typeof file.arrayBuffer !== 'function') fail('SIMPLEX_WEB_ADAPTER_FILE', 'file must expose arrayBuffer()');
  var bytesFromFile = new Uint8Array(await file.arrayBuffer());
  if (bytesFromFile.length > maxBytes) fail('SIMPLEX_WEB_ADAPTER_FILE_SIZE', 'file is larger than the configured maximum');
  return bytesFromFile;
}

function fileName(file, fallback) {
  return String(file && file.name || fallback || 'file').slice(0, 255);
}

function fileMime(file) {
  return String(file && (file.type || file.mime) || '').slice(0, 128);
}

function timeoutError(error) {
  return error && error.code === 'SIMPLEX_CLIENT_TIMEOUT';
}

function makeReceipt(ref, status = 'sent') {
  return {
    accepted: true,
    transport_status: status,
    message_ref: ref
  };
}

function receivedToFacadeMessage(received) {
  var ref = received && received.msgId ? 'rcv:' + encodeBase64Url(received.msgId) : generatedMessageRef('rcv');
  var file = received && received.file ? received.file : null;
  return {
    direction: 'incoming',
    message_ref: ref,
    message_kind: file ? 'file' : 'text',
    delivery_status: 'received',
    created_at: received && received.timestamp ? String(received.timestamp) : new Date().toISOString(),
    text: received && received.text ? received.text : '',
    attachment: file ? {
      name: String(file.name || file.fileName || ''),
      mime: String(file.mime || ''),
      size: Number(file.size || 0) || 0
    } : null
  };
}

function createXftpWebFileTransferClient(xftpWebClient) {
  return {
    async uploadFile(bytes, options = {}) {
      var uploaded = await uploadXftpWebFile(xftpWebClient, bytes, {
        fileName: options.name || 'file',
        fileExtra: options.mime || null,
        key: options.rootKey || options.fileRootKey,
        nonce: options.nonce,
        serverAddress: options.serverAddress
      });
      var manifest = {
        ...uploaded.recipientDescription,
        key: undefined,
        fileName: uploaded.recipientDescription.fileName,
        mime: options.mime || ''
      };
      delete manifest.key;
      return {
        manifest,
        rootKey: uploaded.recipientDescription.key,
        uploadedChunks: uploaded.recipientDescription.chunks.length,
        senderDescription: uploaded.senderDescription
      };
    },
    async downloadFile(manifest, rootKey, options = {}) {
      var downloaded = await downloadXftpWebFile(xftpWebClient, {
        ...(manifest || {}),
        key: rootKey
      }, options);
      return downloaded.content;
    }
  };
}

function normalizeAdapterOptions(options, params) {
  return {
    ...(options || {}),
    ...(params && typeof params === 'object' ? params : {})
  };
}

export function createSimplexWebTransportAdapter(options = {}) {
  return new SimplexWebTransportAdapter(options);
}

export class SimplexWebTransportAdapter {
  constructor(options = {}) {
    this.options = options;
    this.transport = options.transport || null;
    this.xftpWebClient = options.xftpWebClient || null;
    this.simplexClient = options.client || null;
    this.store = options.store || null;
    this.contactClient = options.contactClient || null;
    this.history = [];
    this.receipts = new Map();
    this.connected = !!this.contactClient;
  }

  async connect(params = {}) {
    var config = normalizeAdapterOptions(this.options, params);
    if (!this.transport && !this.contactClient) {
      var smp = config.smp || {};
      var url = config.smpWebSocketUrl || config.smp_url || smp.url;
      if (!url) fail('SIMPLEX_WEB_ADAPTER_SMP', 'SMP WebSocket URL is required');
      this.transport = await connectBrowserSmpWebSocketTransport({
        ...smp,
        url,
        keyHash: decodeConfigBytes(config.smpKeyHash || config.smp_key_hash || smp.keyHash, 'SMP key hash')
      });
    }

    if (!this.xftpWebClient && (config.xftp || config.xftpWebUrl || config.xftp_web_url)) {
      var xftp = config.xftp || {};
      this.xftpWebClient = await connectBrowserXftpWebClient({
        ...xftp,
        url: config.xftpWebUrl || config.xftp_web_url || xftp.url,
        keyHash: decodeConfigBytes(config.xftpKeyHash || config.xftp_key_hash || xftp.keyHash, 'XFTP key hash')
      });
    }

    this.simplexClient = this.simplexClient || config.client || createBrowserSimplexClient({
      ...config,
      transport: this.transport
    });
    this.store = this.store || config.store || createBrowserSimplexStore({
      ...(config.storeOptions || {}),
      namespace: config.namespace || (config.storeOptions && config.storeOptions.namespace) || 'simplex-web'
    });
    var xftpClient = config.xftpClient || (this.xftpWebClient ? createXftpWebFileTransferClient(this.xftpWebClient) : null);
    this.contactClient = this.contactClient || config.contactClient || createBrowserSimplexContactClient({
      ...config,
      client: this.simplexClient,
      store: this.store,
      xftpClient
    });
    this.connected = true;
    return this.getStatus();
  }

  async ensureReady() {
    if (!this.contactClient) await this.connect();
    if (!this.contactClient) fail('SIMPLEX_WEB_ADAPTER_CONNECT', 'browser SimpleX contact client is not connected');
    return this.contactClient;
  }

  getStatus() {
    var transportStatus = this.transport && typeof this.transport.getStatus === 'function'
      ? this.transport.getStatus()
      : null;
    return {
      transport_status: this.connected ? 'direct-browser-smp' : 'configured',
      transport_error: '',
      connected: this.connected,
      plaintextBridge: false,
      browserNativeProtocol: true,
      contactCount: this.contactClient && typeof this.contactClient.listContacts === 'function'
        ? this.contactClient.listContacts().length
        : 0,
      transport: transportStatus
    };
  }

  async sendText(message = {}) {
    var contacts = await this.ensureReady();
    var contactId = safeContactId(message.contact_id || message.contactId || this.options.defaultContactId);
    var text = safeText(message.text);
    var ref = String(message.client_message_id || message.clientMessageId || message.message_ref || generatedMessageRef('snd'));
    await contacts.sendText(contactId, text, {
      clientMessageId: ref,
      corrId: message.corr_id || message.corrId,
      timeoutMs: message.timeout_ms || message.timeoutMs
    });
    var receipt = makeReceipt(ref, 'sent');
    this.receipts.set(ref, receipt);
    this.history.push({
      direction: 'outgoing',
      message_ref: ref,
      message_kind: 'text',
      delivery_status: 'sent',
      created_at: new Date().toISOString(),
      text
    });
    return receipt;
  }

  async sendFiles(message = {}) {
    var contacts = await this.ensureReady();
    var contactId = safeContactId(message.contact_id || message.contactId || this.options.defaultContactId);
    var files = Array.isArray(message.files) ? message.files : Array.from(message.files || []);
    if (!files.length) fail('SIMPLEX_WEB_ADAPTER_FILE', 'at least one file is required');
    var maxBytes = Math.max(1, Math.floor(Number(message.max_file_bytes || message.maxFileBytes || this.options.maxFileBytes || (25 * 1024 * 1024)) || (25 * 1024 * 1024)));
    var receipts = [];
    for (var i = 0; i < files.length; i += 1) {
      var file = files[i];
      var ref = String(message.client_message_id || message.clientMessageId || generatedMessageRef('file')) + (files.length > 1 ? '-' + i : '');
      var bytes = await readFileBytes(file, maxBytes);
      var sent = await contacts.sendFile(contactId, bytes, {
        clientMessageId: ref,
        name: fileName(file, ref),
        mime: fileMime(file),
        timeoutMs: message.timeout_ms || message.timeoutMs
      });
      var receipt = {
        ...makeReceipt(ref, 'sent'),
        attachment: {
          name: fileName(file, ref),
          mime: fileMime(file),
          size: bytes.length
        },
        file: sent.file
      };
      this.receipts.set(ref, receipt);
      this.history.push({
        direction: 'outgoing',
        message_ref: ref,
        message_kind: 'file',
        delivery_status: 'sent',
        created_at: new Date().toISOString(),
        text: '',
        attachment: receipt.attachment
      });
      receipts.push(receipt);
    }
    return receipts;
  }

  async getMessages(query = {}) {
    var contacts = await this.ensureReady();
    var contactId = safeContactId(query.contact_id || query.contactId || this.options.defaultContactId);
    var limit = Math.max(1, Math.min(200, Math.floor(Number(query.limit || query.count || DEFAULT_RECEIVE_LIMIT) || DEFAULT_RECEIVE_LIMIT)));
    var messages = [];
    for (var i = 0; i < limit; i += 1) {
      try {
        var received = await contacts.receiveNext(contactId, {
          timeoutMs: query.timeout_ms || query.timeoutMs || this.options.receiveTimeoutMs || 100,
          acknowledge: query.acknowledge !== false
        });
        var facadeMessage = receivedToFacadeMessage(received);
        messages.push(facadeMessage);
        this.history.push(facadeMessage);
      } catch (error) {
        if (timeoutError(error)) break;
        throw error;
      }
    }
    return messages;
  }

  async getMessageStatus(message = {}) {
    var ref = String(message.message_ref || message.messageRef || message.client_message_id || message.clientMessageId || '');
    if (!ref) fail('SIMPLEX_WEB_ADAPTER_MESSAGE_REF', 'message ref is required');
    return this.receipts.get(ref) || makeReceipt(ref, 'unknown');
  }

  async createInvitation(params = {}) {
    var contacts = await this.ensureReady();
    return contacts.createInvitation({
      ...params,
      id: safeContactId(params.contact_id || params.contactId || params.id || this.options.defaultContactId)
    });
  }

  invitationUri(contactId) {
    if (!this.contactClient) fail('SIMPLEX_WEB_ADAPTER_CONNECT', 'browser SimpleX contact client is not connected');
    return this.contactClient.invitationUri(safeContactId(contactId || this.options.defaultContactId));
  }

  async requestContact(params = {}) {
    var contacts = await this.ensureReady();
    return contacts.requestContact(
      safeContactId(params.contact_id || params.contactId || params.id || this.options.defaultContactId),
      params.invitation_uri || params.invitationUri || params.contact_link || params.contactLink,
      params
    );
  }

  async receiveContactRequest(params = {}) {
    var contacts = await this.ensureReady();
    return contacts.receiveContactRequest(
      safeContactId(params.contact_id || params.contactId || params.id || this.options.defaultContactId),
      params
    );
  }

  async receiveContactAccept(params = {}) {
    var contacts = await this.ensureReady();
    return contacts.receiveContactAccept(
      safeContactId(params.contact_id || params.contactId || params.id || this.options.defaultContactId),
      params
    );
  }

  activateContact(params = {}) {
    if (!this.contactClient) fail('SIMPLEX_WEB_ADAPTER_CONNECT', 'browser SimpleX contact client is not connected');
    return this.contactClient.activateContact(
      safeContactId(params.contact_id || params.contactId || params.id || this.options.defaultContactId),
      params
    );
  }

  listContacts() {
    return this.contactClient && typeof this.contactClient.listContacts === 'function'
      ? this.contactClient.listContacts()
      : [];
  }

  drainDueRetries(options = {}) {
    if (!this.contactClient) return Promise.resolve([]);
    return this.contactClient.drainDueRetries(options);
  }

  disconnect() {
    if (this.transport && typeof this.transport.close === 'function') this.transport.close();
    if (this.xftpWebClient && typeof this.xftpWebClient.close === 'function') this.xftpWebClient.close();
    this.connected = false;
    return Promise.resolve();
  }
}

export function registerSimplexWebTransportAdapter(options = {}, facade = globalThis.SimplexWebTransport) {
  var adapter = createSimplexWebTransportAdapter(options);
  if (!facade || typeof facade.registerBrowserTransport !== 'function') {
    fail('SIMPLEX_WEB_ADAPTER_FACADE', 'window.SimplexWebTransport.registerBrowserTransport is not available');
  }
  return facade.registerBrowserTransport(adapter);
}

export default {
  SimplexWebTransportAdapter,
  SimplexWebTransportAdapterError,
  createSimplexWebTransportAdapter,
  registerSimplexWebTransportAdapter
};
