(function (global) {
  'use strict';

  var STORAGE_PREFIX = 'simplex-web-session-v1';
  var MAX_MESSAGES = 50;
  var MAX_UPLOADS = 20;

  function clampCount(value, fallback) {
    var count = Number(value);
    if (!isFinite(count) || count < 0) {
      return fallback;
    }
    return Math.floor(count);
  }

  function normalizeKeyPart(value, fallback) {
    var raw = String(value == null ? '' : value).trim().toLowerCase();
    raw = raw.replace(/[^a-z0-9._:-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    raw = raw.replace(/(^|[-:.])\.+(?=$|[-:.])/g, '$1');
    raw = raw.replace(/-+/g, '-').replace(/(^[-:.]+|[-:.]+$)/g, '');
    return raw || fallback;
  }

  function buildStorageKey(siteKey, accountKey) {
    return [
      STORAGE_PREFIX,
      normalizeKeyPart(siteKey, 'site'),
      normalizeKeyPart(accountKey, 'anonymous')
    ].join(':');
  }

  function normalizeAttachment(value) {
    var next = value && typeof value === 'object' ? value : null;
    if (!next) {
      return null;
    }
    return {
      name: String(next.name || ''),
      mime: String(next.mime || ''),
      size: clampCount(next.size, 0),
      upload_id: String(next.upload_id || '')
    };
  }

  function normalizeMessage(value) {
    var next = value && typeof value === 'object' ? value : {};
    return {
      seq: clampCount(next.seq, 0),
      direction: String(next.direction || 'outgoing'),
      message_ref: String(next.message_ref || ''),
      message_kind: String(next.message_kind || 'text'),
      delivery_status: String(next.delivery_status || 'queued'),
      created_at: String(next.created_at || ''),
      updated_at: String(next.updated_at || ''),
      text: String(next.text || ''),
      attachment: normalizeAttachment(next.attachment),
      error_code: String(next.error_code || ''),
      error_detail: String(next.error_detail || '')
    };
  }

  function normalizeUpload(value) {
    var next = value && typeof value === 'object' ? value : {};
    return {
      upload_id: String(next.upload_id || ''),
      name: String(next.name || ''),
      status: String(next.status || 'queued'),
      progress: clampCount(next.progress, 0),
      created_at: String(next.created_at || ''),
      error: String(next.error || '')
    };
  }

  function normalizeSession(value) {
    var next = value && typeof value === 'object' ? value : {};
    var messages = Array.isArray(next.messages) ? next.messages.map(normalizeMessage) : [];
    var uploads = Array.isArray(next.uploads) ? next.uploads.map(normalizeUpload) : [];
    messages = messages.slice(-MAX_MESSAGES);
    uploads = uploads.slice(-MAX_UPLOADS);
    var inferredLastSeq = messages.reduce(function (maxSeq, message) {
      var seq = clampCount(message.seq, 0);
      return seq > maxSeq ? seq : maxSeq;
    }, 0);
    return {
      version: 1,
      draftText: String(next.draftText || ''),
      lastSeq: clampCount(next.lastSeq, inferredLastSeq),
      messages: messages,
      uploads: uploads,
      savedAt: String(next.savedAt || '')
    };
  }

  function storageOrGlobal(storage) {
    if (storage && typeof storage.getItem === 'function' && typeof storage.setItem === 'function') {
      return storage;
    }
    return global && global.localStorage ? global.localStorage : null;
  }

  function emptySession() {
    return normalizeSession({});
  }

  function readSession(storage, siteKey, accountKey) {
    var target = storageOrGlobal(storage);
    if (!target) {
      return emptySession();
    }
    try {
      return normalizeSession(JSON.parse(String(target.getItem(buildStorageKey(siteKey, accountKey)) || 'null')));
    } catch (_err) {
      return emptySession();
    }
  }

  function writeSession(storage, siteKey, accountKey, value) {
    var target = storageOrGlobal(storage);
    var normalized = normalizeSession(value);
    normalized.savedAt = new Date().toISOString();
    if (!target) {
      return normalized;
    }
    try {
      target.setItem(buildStorageKey(siteKey, accountKey), JSON.stringify(normalized));
    } catch (_err) {
      return normalized;
    }
    return normalized;
  }

  function clearSession(storage, siteKey, accountKey) {
    var target = storageOrGlobal(storage);
    if (!target) {
      return false;
    }
    try {
      target.removeItem(buildStorageKey(siteKey, accountKey));
      return true;
    } catch (_err) {
      return false;
    }
  }

  var api = {
    STORAGE_PREFIX: STORAGE_PREFIX,
    MAX_MESSAGES: MAX_MESSAGES,
    MAX_UPLOADS: MAX_UPLOADS,
    buildStorageKey: buildStorageKey,
    normalizeSession: normalizeSession,
    readSession: readSession,
    writeSession: writeSession,
    clearSession: clearSession
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  global.SimplexWebSessionStore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
