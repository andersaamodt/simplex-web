(function (global) {
  'use strict';

  var STORAGE_PREFIX = 'simplex-web-session-v1';
  var MAX_MESSAGES = 50;
  var MAX_UPLOADS = 20;
  var MAX_TEXT_LENGTH = 4000;
  var MAX_LABEL_LENGTH = 256;
  var MAX_STATUS_LENGTH = 64;
  var MAX_KEY_PART_LENGTH = 96;
  var MAX_STORED_JSON_LENGTH = 262144;

  function clampCount(value, fallback) {
    var count = Number(value);
    if (!isFinite(count) || count < 0) {
      return fallback;
    }
    return Math.floor(count);
  }

  function clampProgress(value) {
    var progress = clampCount(value, 0);
    if (progress > 100) {
      return 100;
    }
    return progress;
  }

  function limitString(value, maxLength) {
    return String(value == null ? '' : value).slice(0, maxLength);
  }

  function normalizeDirection(value) {
    return String(value == null ? '' : value).trim().toLowerCase() === 'incoming' ? 'incoming' : 'outgoing';
  }

  function normalizeMessageKind(value) {
    return String(value == null ? '' : value).trim().toLowerCase() === 'file' ? 'file' : 'text';
  }

  function normalizeKeyPart(value, fallback) {
    var raw = String(value == null ? '' : value).trim().toLowerCase();
    raw = raw.replace(/[^a-z0-9._:-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    raw = raw.replace(/(^|[-:.])\.+(?=$|[-:.])/g, '$1');
    raw = raw.replace(/-+/g, '-').replace(/(^[-:.]+|[-:.]+$)/g, '');
    raw = raw.slice(0, MAX_KEY_PART_LENGTH);
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
      name: limitString(next.name || '', MAX_LABEL_LENGTH),
      mime: limitString(next.mime || '', MAX_LABEL_LENGTH),
      size: clampCount(next.size, 0),
      upload_id: limitString(next.upload_id || '', MAX_LABEL_LENGTH)
    };
  }

  function normalizeMessage(value) {
    var next = value && typeof value === 'object' ? value : {};
    return {
      seq: clampCount(next.seq, 0),
      direction: normalizeDirection(next.direction),
      message_ref: limitString(next.message_ref || '', MAX_LABEL_LENGTH),
      message_kind: normalizeMessageKind(next.message_kind),
      delivery_status: limitString(next.delivery_status || 'queued', MAX_STATUS_LENGTH),
      created_at: limitString(next.created_at || '', MAX_LABEL_LENGTH),
      updated_at: limitString(next.updated_at || '', MAX_LABEL_LENGTH),
      text: limitString(next.text || '', MAX_TEXT_LENGTH),
      attachment: normalizeAttachment(next.attachment),
      error_code: limitString(next.error_code || '', MAX_LABEL_LENGTH),
      error_detail: limitString(next.error_detail || '', MAX_TEXT_LENGTH)
    };
  }

  function normalizeUpload(value) {
    var next = value && typeof value === 'object' ? value : {};
    return {
      upload_id: limitString(next.upload_id || '', MAX_LABEL_LENGTH),
      name: limitString(next.name || '', MAX_LABEL_LENGTH),
      status: limitString(next.status || 'queued', MAX_STATUS_LENGTH),
      progress: clampProgress(next.progress),
      created_at: limitString(next.created_at || '', MAX_LABEL_LENGTH),
      error: limitString(next.error || '', MAX_TEXT_LENGTH)
    };
  }

  function normalizeSession(value) {
    var next = value && typeof value === 'object' ? value : {};
    var messages = Array.isArray(next.messages) ? next.messages.slice(-MAX_MESSAGES).map(normalizeMessage) : [];
    var uploads = Array.isArray(next.uploads) ? next.uploads.slice(-MAX_UPLOADS).map(normalizeUpload) : [];
    var inferredLastSeq = messages.reduce(function (maxSeq, message) {
      var seq = clampCount(message.seq, 0);
      return seq > maxSeq ? seq : maxSeq;
    }, 0);
    return {
      version: 1,
      draftText: limitString(next.draftText || '', MAX_TEXT_LENGTH),
      lastSeq: clampCount(next.lastSeq, inferredLastSeq),
      messages: messages,
      uploads: uploads,
      savedAt: limitString(next.savedAt || '', MAX_LABEL_LENGTH)
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
    var rawValue;
    if (!target) {
      return emptySession();
    }
    try {
      rawValue = String(target.getItem(buildStorageKey(siteKey, accountKey)) || 'null');
      if (rawValue.length > MAX_STORED_JSON_LENGTH) {
        return emptySession();
      }
      return normalizeSession(JSON.parse(rawValue));
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
    MAX_KEY_PART_LENGTH: MAX_KEY_PART_LENGTH,
    MAX_STORED_JSON_LENGTH: MAX_STORED_JSON_LENGTH,
    clampProgress: clampProgress,
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
