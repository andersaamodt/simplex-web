// SPDX-License-Identifier: AGPL-3.0-only
//
// Durable browser store for queue/contact/client state.
//
// The store is deliberately boring: one JSON document per record in a
// caller-provided Storage-like backend. Browser deployments can pass
// `localStorage`; tests can pass an in-memory Map wrapper. Binary protocol
// values are tagged as base64url strings so hand-edited storage cannot be
// confused with ordinary text fields.

import { decodeBase64Url, encodeBase64Url, toBytes } from './browser-smp-core.mjs';

export const SIMPLEX_STORE_SCHEMA = 1;
export const SIMPLEX_STORE_PREFIX = 'simplex-web-v1';
export const SIMPLEX_STORE_MAX_RECORD_BYTES = 262144;
export const SIMPLEX_STORE_MAX_LIST_ITEMS = 1000;

export class BrowserSimplexStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSimplexStoreError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserSimplexStoreError(code, message);
}

function safePart(value, label = 'key') {
  var text = String(value == null ? '' : value).trim();
  if (!text || text.length > 160 || /[^A-Za-z0-9_.:-]/.test(text)) {
    fail('SIMPLEX_STORE_KEY', label + ' must be 1 to 160 safe ASCII characters');
  }
  return text;
}

function storageKey(namespace, type, id) {
  return SIMPLEX_STORE_PREFIX + ':' + safePart(namespace, 'namespace') + ':' + safePart(type, 'record type') + ':' + safePart(id, 'record id');
}

function listKey(namespace, type) {
  return SIMPLEX_STORE_PREFIX + ':' + safePart(namespace, 'namespace') + ':list:' + safePart(type, 'record type');
}

function binary(value) {
  return { $bytes: encodeBase64Url(toBytes(value || new Uint8Array(), 'stored bytes')) };
}

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function encodeValue(value) {
  if (value instanceof Uint8Array || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return binary(value);
  if (Array.isArray(value)) return value.slice(0, SIMPLEX_STORE_MAX_LIST_ITEMS).map(encodeValue);
  if (isPlainObject(value)) {
    var out = {};
    for (var [key, child] of Object.entries(value)) {
      if (/^[A-Za-z0-9_$.-]{1,80}$/.test(key)) out[key] = encodeValue(child);
    }
    return out;
  }
  if (typeof value === 'bigint') return { $bigint: String(value) };
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
  if (typeof value === 'boolean' || value == null) return value;
  return String(value).slice(0, 8192);
}

function decodeValue(value) {
  if (Array.isArray(value)) return value.map(decodeValue);
  if (isPlainObject(value)) {
    if (typeof value.$bytes === 'string') return decodeBase64Url(value.$bytes, 'stored bytes');
    if (typeof value.$bigint === 'string') return BigInt(value.$bigint);
    var out = {};
    for (var [key, child] of Object.entries(value)) out[key] = decodeValue(child);
    return out;
  }
  return value;
}

function serialize(record) {
  var text = JSON.stringify({ schema: SIMPLEX_STORE_SCHEMA, record: encodeValue(record) });
  if (text.length > SIMPLEX_STORE_MAX_RECORD_BYTES) fail('SIMPLEX_STORE_SIZE', 'stored record is too large');
  return text;
}

function deserialize(text) {
  if (!text) return null;
  if (String(text).length > SIMPLEX_STORE_MAX_RECORD_BYTES) fail('SIMPLEX_STORE_SIZE', 'stored record is too large');
  var parsed;
  try {
    parsed = JSON.parse(String(text));
  } catch (_error) {
    fail('SIMPLEX_STORE_JSON', 'stored record is not valid JSON');
  }
  if (!parsed || parsed.schema !== SIMPLEX_STORE_SCHEMA) fail('SIMPLEX_STORE_SCHEMA', 'stored record schema is unsupported');
  return decodeValue(parsed.record);
}

function memoryStorage() {
  var map = new Map();
  return {
    getItem(key) { return map.has(key) ? map.get(key) : null; },
    setItem(key, value) { map.set(String(key), String(value)); },
    removeItem(key) { map.delete(String(key)); },
    key(index) { return Array.from(map.keys())[index] || null; },
    get length() { return map.size; }
  };
}

function readList(storage, namespace, type) {
  var raw = storage.getItem(listKey(namespace, type));
  if (!raw) return [];
  var parsed = deserialize(raw);
  return Array.isArray(parsed) ? parsed.map((item) => safePart(item, 'stored id')) : [];
}

function writeList(storage, namespace, type, ids) {
  var clean = Array.from(new Set(ids.map((id) => safePart(id, 'stored id')))).slice(0, SIMPLEX_STORE_MAX_LIST_ITEMS);
  storage.setItem(listKey(namespace, type), serialize(clean));
}

export function createBrowserSimplexStore(options = {}) {
  return new BrowserSimplexStore(options);
}

export class BrowserSimplexStore {
  constructor(options = {}) {
    this.storage = options.storage || (typeof localStorage !== 'undefined' ? localStorage : memoryStorage());
    this.namespace = safePart(options.namespace || 'default', 'namespace');
  }

  save(type, id, record) {
    var cleanType = safePart(type, 'record type');
    var cleanId = safePart(id, 'record id');
    this.storage.setItem(storageKey(this.namespace, cleanType, cleanId), serialize({
      id: cleanId,
      updatedAt: new Date().toISOString(),
      value: record || {}
    }));
    var ids = readList(this.storage, this.namespace, cleanType);
    if (!ids.includes(cleanId)) writeList(this.storage, this.namespace, cleanType, ids.concat(cleanId));
    return cleanId;
  }

  load(type, id) {
    var stored = deserialize(this.storage.getItem(storageKey(this.namespace, type, id)));
    return stored ? stored.value : null;
  }

  list(type) {
    return readList(this.storage, this.namespace, type).map((id) => ({ id, value: this.load(type, id) })).filter((row) => !!row.value);
  }

  delete(type, id) {
    var cleanType = safePart(type, 'record type');
    var cleanId = safePart(id, 'record id');
    this.storage.removeItem(storageKey(this.namespace, cleanType, cleanId));
    writeList(this.storage, this.namespace, cleanType, readList(this.storage, this.namespace, cleanType).filter((item) => item !== cleanId));
  }

  saveQueue(id, queue) { return this.save('queue', id, queue); }
  loadQueue(id) { return this.load('queue', id); }
  listQueues() { return this.list('queue'); }
  deleteQueue(id) { return this.delete('queue', id); }
  saveContact(id, contact) { return this.save('contact', id, contact); }
  loadContact(id) { return this.load('contact', id); }
  listContacts() { return this.list('contact'); }
  deleteContact(id) { return this.delete('contact', id); }
  saveRatchet(id, ratchet) { return this.save('ratchet', id, ratchet); }
  loadRatchet(id) { return this.load('ratchet', id); }
  deleteRatchet(id) { return this.delete('ratchet', id); }

  enqueuePending(id, task) {
    var queue = this.load('pending', 'queue') || [];
    var cleanId = safePart(id, 'pending id');
    var next = queue.filter((item) => item.id !== cleanId).concat({ id: cleanId, task: task || {}, attempts: 0 });
    this.save('pending', 'queue', next.slice(-SIMPLEX_STORE_MAX_LIST_ITEMS));
  }

  listPending() {
    return this.load('pending', 'queue') || [];
  }

  replacePending(items) {
    this.save('pending', 'queue', (Array.isArray(items) ? items : []).slice(0, SIMPLEX_STORE_MAX_LIST_ITEMS));
  }

  deletePendingWhere(predicate) {
    var test = typeof predicate === 'function' ? predicate : () => false;
    var next = this.listPending().filter((item) => !test(item));
    this.replacePending(next);
    return next;
  }
}

export default {
  BrowserSimplexStore,
  BrowserSimplexStoreError,
  SIMPLEX_STORE_PREFIX,
  SIMPLEX_STORE_SCHEMA,
  createBrowserSimplexStore
};
