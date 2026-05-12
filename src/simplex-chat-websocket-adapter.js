(function (global) {
  'use strict';

  var MAX_TEXT_LENGTH = 4000;
  var MAX_LABEL_LENGTH = 256;
  var DEFAULT_TIMEOUT_MS = 90000;
  var DEFAULT_STATUS_TIMEOUT_MS = 15000;
  var DEFAULT_RETRIES = 10;
  var DEFAULT_RETRY_DELAY_MS = 1000;
  var DEFAULT_RECEIVE_FILE_BYTES = 25 * 1024 * 1024;
  var DEFAULT_RECEIVE_REQUERY_DELAY_MS = 250;
  var ERROR_CONFIG = 'SIMPLEX_CHAT_WS_CONFIG';
  var ERROR_TIMEOUT = 'SIMPLEX_CHAT_WS_TIMEOUT';
  var ERROR_RESPONSE = 'SIMPLEX_CHAT_WS_RESPONSE';
  var ERROR_SECURITY = 'SIMPLEX_CHAT_WS_SECURITY';
  var STORAGE_PREFIX = 'simplex-chat-websocket-adapter-v1';
  var ATTACHMENT_MARKER = 'simplex-web-file:v1:';
  var MAX_ATTACHMENT_DATA_URL_LENGTH = 1200000;
  var pageLifecycleClosing = false;

  function limitString(value, maxLength) {
    return String(value == null ? '' : value).slice(0, maxLength);
  }

  function normalizeCommandAtom(value, label, allowEmpty) {
    var raw = limitString(value, MAX_LABEL_LENGTH).replace(/^@/, '').trim();
    if (!raw) {
      if (allowEmpty) return '';
      throw makeError(ERROR_CONFIG, 'SimpleX Chat ' + label + ' is required');
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(raw)) {
      throw makeError(ERROR_CONFIG, 'SimpleX Chat ' + label + ' contains unsupported command characters');
    }
    return raw;
  }

  function normalizeContactLink(value, allowEmpty) {
    var raw = limitString(value, MAX_TEXT_LENGTH).trim();
    if (!raw) {
      if (allowEmpty) return '';
      throw makeError(ERROR_CONFIG, 'SimpleX Chat contact link is required');
    }
    if (/[\x00-\x20\x7f]/.test(raw)) {
      throw makeError(ERROR_CONFIG, 'SimpleX Chat contact link contains unsupported command characters');
    }
    if (!/^(simplex:|https:\/\/)/i.test(raw)) {
      throw makeError(ERROR_CONFIG, 'SimpleX Chat contact link must be a simplex: or https:// link');
    }
    return raw;
  }

  function isAbsoluteLocalPath(path) {
    var value = String(path || '').trim();
    return /^[A-Za-z]:[\\/]/.test(value) || value.charAt(0) === '/';
  }

  function isSafeRelativeFilePath(path) {
    var value = String(path || '').trim();
    if (!value || isAbsoluteLocalPath(value)) return false;
    if (/[\x00-\x1f\x7f]/.test(value)) return false;
    if (/[\\/]/.test(value)) return false;
    if (value === '.' || value === '..') return false;
    return true;
  }

  function safeMimeHeader(value) {
    var raw = limitString(value || 'application/octet-stream', MAX_LABEL_LENGTH).trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*(?:;[a-z0-9=.+ -]+)?$/.test(raw)) {
      return 'application/octet-stream';
    }
    return raw;
  }

  function makeError(code, message) {
    var error = new Error(message);
    error.name = 'SimplexChatWebSocketAdapterError';
    error.code = code;
    return error;
  }

  function markPageLifecycleClosing() {
    pageLifecycleClosing = true;
  }

  function clearPageLifecycleClosing() {
    pageLifecycleClosing = false;
  }

  function isPageLifecycleClosing() {
    return pageLifecycleClosing;
  }

  if (global && typeof global.addEventListener === 'function') {
    global.addEventListener('beforeunload', markPageLifecycleClosing);
    global.addEventListener('pagehide', markPageLifecycleClosing);
    global.addEventListener('pageshow', clearPageLifecycleClosing);
  }

  function normalizeUrl(value) {
    var raw = String(value || '').trim();
    if (!raw) return '';
    try {
      return new URL(raw, global.location && global.location.href || 'http://127.0.0.1/').href;
    } catch (_err) {
      return '';
    }
  }

  function isLoopbackHost(hostname) {
    var host = String(hostname || '').toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  }

  function validateWebSocketUrl(url, allowRemote) {
    var parsed;
    try {
      parsed = new URL(url);
    } catch (_err) {
      throw makeError(ERROR_CONFIG, 'A valid SimpleX Chat WebSocket URL is required');
    }
    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
      throw makeError(ERROR_CONFIG, 'SimpleX Chat WebSocket URL must use ws:// or wss://');
    }
    if (!allowRemote && !isLoopbackHost(parsed.hostname)) {
      throw makeError(ERROR_SECURITY, 'Remote SimpleX Chat WebSocket endpoints must opt in with allowRemote: true');
    }
    return parsed.href;
  }

  function normalizeLoopbackHttpUrl(value, allowRemote) {
    var raw = String(value || '').trim();
    if (!raw) return '';
    var parsed;
    try {
      parsed = new URL(raw, global.location && global.location.href || 'http://127.0.0.1/');
    } catch (_err) {
      throw makeError(ERROR_CONFIG, 'A valid SimpleX file bridge URL is required');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw makeError(ERROR_CONFIG, 'SimpleX file bridge URL must use http:// or https://');
    }
    if (!allowRemote && !isLoopbackHost(parsed.hostname)) {
      throw makeError(ERROR_SECURITY, 'Remote SimpleX file bridge endpoints must opt in with allowRemoteFileBridge: true');
    }
    return parsed.href.replace(/\/+$/, '');
  }

  function normalizeConfig(options) {
    var opts = options && typeof options === 'object' ? options : {};
    var url = normalizeUrl(opts.url || opts.webSocketUrl || opts.websocketUrl || opts.endpoint || '');
    var userId = limitString(opts.user_id || opts.userId || opts.active_user_id || opts.activeUserId || '', MAX_LABEL_LENGTH).trim();
    var fetchImpl = opts.fetchImpl || null;
    if (fetchImpl && fetchImpl === global.fetch && typeof fetchImpl === 'function' && global) {
      fetchImpl = fetchImpl.bind(global);
    }
    return {
      url: validateWebSocketUrl(url, opts.allowRemote === true),
      user_id: userId,
      file_bridge_url: normalizeLoopbackHttpUrl(opts.file_bridge_url || opts.fileBridgeUrl || '', opts.allowRemoteFileBridge === true),
      timeout_ms: Math.max(1000, Math.floor(Number(opts.timeout_ms || opts.timeoutMs || DEFAULT_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS)),
      status_timeout_ms: Math.max(1000, Math.floor(Number(opts.status_timeout_ms || opts.statusTimeoutMs || DEFAULT_STATUS_TIMEOUT_MS) || DEFAULT_STATUS_TIMEOUT_MS)),
      retries: Math.max(1, Math.floor(Number(opts.retries || DEFAULT_RETRIES) || DEFAULT_RETRIES)),
      retry_delay_ms: Math.max(100, Math.floor(Number(opts.retry_delay_ms || opts.retryDelayMs || DEFAULT_RETRY_DELAY_MS) || DEFAULT_RETRY_DELAY_MS)),
      max_receive_file_bytes: Math.max(1, Math.floor(Number(opts.max_receive_file_bytes || opts.maxReceiveFileBytes || DEFAULT_RECEIVE_FILE_BYTES) || DEFAULT_RECEIVE_FILE_BYTES)),
      receive_requery_delay_ms: Math.max(100, Math.floor(Number(opts.receive_requery_delay_ms || opts.receiveRequeryDelayMs || DEFAULT_RECEIVE_REQUERY_DELAY_MS) || DEFAULT_RECEIVE_REQUERY_DELAY_MS)),
      storage: opts.storage || null,
      fetchImpl: fetchImpl,
      WebSocketImpl: opts.WebSocketImpl || global.WebSocket
    };
  }

  function parseEnvelope(value) {
    try {
      return JSON.parse(String(value || ''));
    } catch (_err) {
      return null;
    }
  }

  function responseType(resp) {
    return String(resp && resp.type || '');
  }

  function chatItemStatus(chatItem) {
    var itemStatus = chatItem && chatItem.meta && chatItem.meta.itemStatus;
    var type = String(itemStatus && itemStatus.type || '');
    if (type === 'sndNew') return 'sending';
    if (type === 'sndRcvd') return 'delivered';
    if (type === 'sndSent') return 'sent';
    if (type === 'sndWarning') return 'warning';
    if (type === 'sndError' || type === 'sndErrorAuth') return 'failed';
    return type || 'sent';
  }

  function firstChatItem(resp) {
    var items = Array.isArray(resp && resp.chatItems) ? resp.chatItems : [];
    return items.length && items[0] && items[0].chatItem ? items[0].chatItem : null;
  }

  function responseChatItems(resp) {
    if (Array.isArray(resp && resp.chatItems)) {
      return resp.chatItems.map(function (wrapped) {
        return wrapped && wrapped.chatItem ? wrapped.chatItem : wrapped;
      }).filter(Boolean);
    }
    if (resp && resp.chat && Array.isArray(resp.chat.chatItems)) {
      return resp.chat.chatItems.filter(Boolean);
    }
    return [];
  }

  function chatItemText(chatItem) {
    if (!chatItem || !chatItem.content) return '';
    var content = chatItem.content;
    var msgContent = content.msgContent || content.content || null;
    if (msgContent && typeof msgContent.text === 'string') {
      return msgContent.text;
    }
    if (chatItem.meta && typeof chatItem.meta.itemText === 'string') {
      return chatItem.meta.itemText;
    }
    return '';
  }

  function base64UrlEncode(value) {
    return String(value || '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function base64UrlDecode(value) {
    var raw = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    while (raw.length % 4) raw += '=';
    return raw;
  }

  function encodeUtf8Base64(value) {
    return btoa(unescape(encodeURIComponent(String(value || ''))));
  }

  function decodeUtf8Base64(value) {
    return decodeURIComponent(escape(atob(String(value || ''))));
  }

  function parseAttachmentMarker(text) {
    var value = String(text || '');
    var idx = value.indexOf(ATTACHMENT_MARKER);
    if (idx < 0) return null;
    var marker = value.slice(idx + ATTACHMENT_MARKER.length).trim().split(/\s+/)[0] || '';
    var parts = marker.split(':');
    if (parts.length < 2) return null;
    try {
      var meta = JSON.parse(decodeUtf8Base64(base64UrlDecode(parts[0])));
      var name = limitString(meta && meta.name || 'Attachment', MAX_LABEL_LENGTH);
      var mime = limitString(meta && meta.mime || '', MAX_LABEL_LENGTH);
      var size = Number(meta && meta.size || 0) || 0;
      var dataBase64 = String(parts[1] || '').replace(/[^A-Za-z0-9+/=]/g, '');
      var dataUrl = dataBase64 && dataBase64.length <= MAX_ATTACHMENT_DATA_URL_LENGTH
        ? 'data:' + (mime || 'application/octet-stream') + ';base64,' + dataBase64
        : '';
      return {
        text: value.slice(0, idx).replace(/\s+$/g, ''),
        attachment: {
          name: name,
          mime: mime,
          size: size,
          data_url: dataUrl
        }
      };
    } catch (_err) {
      return null;
    }
  }

  function chatItemKind(chatItem) {
    var content = chatItem && chatItem.content && (chatItem.content.msgContent || chatItem.content.content || chatItem.content);
    if (content && typeof content.type === 'string') return content.type;
    if (chatItem && chatItem.file) return 'file';
    return 'text';
  }

  function chatItemDirection(chatItem) {
    return chatItem && chatItem.chatDir && chatItem.chatDir.type === 'directRcv' ? 'incoming' : 'outgoing';
  }

  function mimeFromName(name) {
    var value = String(name || '').toLowerCase();
    if (/\.(apng)$/.test(value)) return 'image/apng';
    if (/\.(avif)$/.test(value)) return 'image/avif';
    if (/\.(gif)$/.test(value)) return 'image/gif';
    if (/\.(jpe?g)$/.test(value)) return 'image/jpeg';
    if (/\.(png)$/.test(value)) return 'image/png';
    if (/\.(webp)$/.test(value)) return 'image/webp';
    if (/\.(m4a)$/.test(value)) return 'audio/mp4';
    if (/\.(mp3)$/.test(value)) return 'audio/mpeg';
    if (/\.(ogg|oga)$/.test(value)) return 'audio/ogg';
    if (/\.(wav)$/.test(value)) return 'audio/wav';
    if (/\.(m4v|mp4)$/.test(value)) return 'video/mp4';
    if (/\.(webm)$/.test(value)) return 'video/webm';
    if (/\.(txt|md)$/.test(value)) return 'text/plain';
    return '';
  }

  function chatFileLocalPath(file) {
    var status = file && file.fileStatus && typeof file.fileStatus === 'object' ? file.fileStatus : {};
    var source = file && file.fileSource && typeof file.fileSource === 'object' ? file.fileSource : {};
    var raw = file && (
      file.filePath ||
      file.file_path ||
      file.path ||
      source.filePath ||
      source.file_path ||
      status.filePath ||
      status.file_path ||
      status.path
    );
    raw = raw ? limitString(raw, MAX_TEXT_LENGTH) : '';
    if (isAbsoluteLocalPath(raw)) return raw;
    return isSafeRelativeFilePath(raw) ? raw : '';
  }

  function chatFileStatusType(file) {
    var status = file && file.fileStatus && typeof file.fileStatus === 'object' ? file.fileStatus : {};
    return String(status.type || '');
  }

  function chatFileId(file) {
    var raw = file && file.fileId != null ? String(file.fileId) : '';
    return /^[1-9][0-9]*$/.test(raw) ? raw : '';
  }

  function chatItemNeedsFileReceive(config, chatItem) {
    if (chatItemDirection(chatItem) !== 'incoming') return false;
    var file = chatItem && chatItem.file ? chatItem.file : null;
    if (!file || !chatFileId(file)) return false;
    if (chatFileLocalPath(file)) return false;
    if (Number(file.fileSize || 0) > config.max_receive_file_bytes) return false;
    return chatFileStatusType(file) === 'rcvInvitation';
  }

  function chatItemHasPendingFileReceive(config, chatItem) {
    if (chatItemDirection(chatItem) !== 'incoming') return false;
    var file = chatItem && chatItem.file ? chatItem.file : null;
    if (!file || !chatFileId(file)) return false;
    if (Number(file.fileSize || 0) > config.max_receive_file_bytes) return false;
    var statusType = chatFileStatusType(file);
    return statusType === 'rcvAccepted' || statusType === 'rcvTransfer';
  }

  function bridgedFileUrl(config, filePath) {
    if (!config || !config.file_bridge_url || !filePath) return '';
    return config.file_bridge_url + '/files?path=' + encodeURIComponent(filePath);
  }

  function messageFromChatItem(config, chatItem) {
    var direction = chatItemDirection(chatItem);
    var messageKind = chatItemKind(chatItem);
    var text = chatItemText(chatItem);
    var chatFile = chatItem && chatItem.file ? chatItem.file : null;
    var attachmentName = chatFile && chatFile.fileName ? String(chatFile.fileName) : '';
    var attachmentSize = chatFile && chatFile.fileSize != null ? Number(chatFile.fileSize) : 0;
    var attachmentPath = chatFileLocalPath(chatFile);
    if (
      messageKind === 'file' &&
      attachmentName &&
      /^upl-[^-]+-/.test(attachmentName) &&
      String(text || '').trim()
    ) {
      attachmentName = String(text || '').trim();
    }
    var parsedAttachment = parseAttachmentMarker(text);
    if (parsedAttachment) {
      text = parsedAttachment.text;
      messageKind = 'file';
      attachmentName = parsedAttachment.attachment.name;
      attachmentSize = parsedAttachment.attachment.size;
    }
    var attachmentMime = parsedAttachment && parsedAttachment.attachment
      ? parsedAttachment.attachment.mime
      : mimeFromName(attachmentName);
    var dataUrl = parsedAttachment && parsedAttachment.attachment ? parsedAttachment.attachment.data_url : '';
    var url = dataUrl ? '' : bridgedFileUrl(config, attachmentPath);
    return {
      seq: 0,
      direction: direction,
      message_ref: messageRefFromChatItem(chatItem, ''),
      message_kind: messageKind,
      delivery_status: direction === 'incoming' ? 'received' : chatItemStatus(chatItem),
      created_at: limitString(chatItem && chatItem.meta && (chatItem.meta.itemTs || chatItem.meta.createdAt) || '', MAX_TEXT_LENGTH),
      updated_at: new Date().toISOString(),
      text: text,
      attachment: attachmentName ? {
        name: attachmentName,
        mime: attachmentMime,
        size: Number(attachmentSize || 0) || 0,
        file_path: attachmentPath,
        data_url: dataUrl,
        url: url
      } : null
    };
  }

  function messageRefFromChatItem(chatItem, fallback) {
    return limitString(chatItem && chatItem.meta && chatItem.meta.itemId != null ? String(chatItem.meta.itemId) : fallback, MAX_LABEL_LENGTH);
  }

  function statusReceiptFromChatItem(chatItem, fallback) {
    var itemStatus = chatItem && chatItem.meta && chatItem.meta.itemStatus;
    return {
      accepted: true,
      transport_status: chatItemStatus(chatItem),
      raw_status: limitString(itemStatus && itemStatus.type || '', MAX_LABEL_LENGTH),
      message_ref: messageRefFromChatItem(chatItem, fallback),
      chat_item: chatItem || null
    };
  }

  function statusIsTerminal(status) {
    var raw = String(status || '').trim();
    switch (raw) {
      case 'sending':
      case 'sndNew':
      case 'sent':
      case 'sndSent':
        return false;
      case 'delivered':
      case 'sndRcvd':
      case 'failed':
      case 'sndError':
      case 'sndErrorAuth':
      case 'warning':
      case 'sndWarning':
        return true;
      default:
        return !!raw;
    }
  }

  function emitStatus(payload, receipt) {
    if (!payload || typeof payload.on_status !== 'function') return;
    try {
      payload.on_status(receipt);
    } catch (_err) {
      // UI status callbacks must not interfere with SimpleX command handling.
    }
  }

  function matchingStatusChatItem(resp, messageRef) {
    if (!messageRef || !resp) return null;
    var items = responseChatItems(resp);
    for (var i = 0; i < items.length; i += 1) {
      var chatItem = items[i];
      if (messageRefFromChatItem(chatItem, '') === messageRef) {
        return chatItem;
      }
    }
    return null;
  }

  function contactFromResponse(resp) {
    if (!resp || typeof resp !== 'object') return null;
    if (
      resp.connectionPlan &&
      resp.connectionPlan.contactAddressPlan &&
      resp.connectionPlan.contactAddressPlan.contact
    ) {
      return resp.connectionPlan.contactAddressPlan.contact;
    }
    return resp.contact || resp.toContact || resp.contactInfo || null;
  }

  function contactIdFromResponse(resp) {
    var contact = contactFromResponse(resp);
    var id = contact && (contact.contactId || contact.apiId || contact.id);
    return normalizeCommandAtom(id, 'contact id', true);
  }

  function activeUserIdFromResponse(resp) {
    var user = resp && (resp.user || resp.currentUser || resp.activeUser || resp);
    var id = user && (user.userId || user.user_id || user.id);
    return normalizeCommandAtom(id, 'active user id', true);
  }

  function chatErrorSummary(resp) {
    var chatError = resp && resp.chatError;
    if (!chatError || typeof chatError !== 'object') return '';
    var agentError = chatError.agentError || null;
    if (agentError && typeof agentError === 'object') {
      var brokerErr = agentError.brokerErr && agentError.brokerErr.type ? String(agentError.brokerErr.type) : '';
      var brokerAddress = agentError.brokerAddress ? String(agentError.brokerAddress) : '';
      if (agentError.type || brokerErr || brokerAddress) {
        return [
          agentError.type ? String(agentError.type) : '',
          brokerErr,
          brokerAddress
        ].filter(Boolean).join(' ');
      }
    }
    if (chatError.type) return String(chatError.type);
    try {
      return JSON.stringify(chatError).slice(0, 300);
    } catch (_err) {
      return '';
    }
  }

  function chatErrorType(resp) {
    var chatError = resp && resp.chatError;
    if (!chatError || typeof chatError !== 'object') return '';
    var errorType = chatError.errorType;
    if (errorType && typeof errorType === 'object' && errorType.type) {
      return String(errorType.type);
    }
    if (chatError.type) return String(chatError.type);
    return '';
  }

  function storageOrNull(storage) {
    if (storage && typeof storage.getItem === 'function' && typeof storage.setItem === 'function') {
      return storage;
    }
    return global.localStorage && typeof global.localStorage.getItem === 'function' ? global.localStorage : null;
  }

  function cacheKey(payload, userId, contactLink) {
    var siteKey = limitString(payload.siteKey || payload.site_key || 'site', MAX_LABEL_LENGTH);
    var accountKey = limitString(payload.accountKey || payload.account_key || 'anonymous', MAX_LABEL_LENGTH);
    var linkKey = String(contactLink || '').slice(0, 512);
    return [STORAGE_PREFIX, siteKey, accountKey, userId, linkKey].join(':');
  }

  function cachedContactId(config, payload, userId, contactLink) {
    var storage = storageOrNull(config.storage);
    if (!storage || !contactLink) return '';
    try {
      return normalizeCommandAtom(storage.getItem(cacheKey(payload, userId, contactLink)) || '', 'cached contact id', true);
    } catch (_err) {
      return '';
    }
  }

  function rememberContactId(config, payload, userId, contactLink, contactId) {
    var storage = storageOrNull(config.storage);
    if (!storage || !contactLink || !contactId) return;
    try {
      storage.setItem(cacheKey(payload, userId, contactLink), String(contactId));
    } catch (_err) {
      // Ignore storage failures; the next send can reconnect or use explicit contact ids.
    }
  }

  function forgetContactId(config, payload, userId, contactLink) {
    var storage = storageOrNull(config.storage);
    if (!storage || !contactLink) return;
    try {
      if (typeof storage.removeItem === 'function') {
        storage.removeItem(cacheKey(payload, userId, contactLink));
      } else {
        storage.setItem(cacheKey(payload, userId, contactLink), '');
      }
    } catch (_err) {
      // Ignore storage failures; the current send can still reconnect with the link.
    }
  }

  function textComposedMessage(text) {
    return {
      msgContent: {
        type: 'text',
        text: limitString(text || '', MAX_TEXT_LENGTH)
      },
      mentions: {}
    };
  }

  function fileName(file) {
    return limitString(file && file.name || 'attachment.bin', MAX_LABEL_LENGTH);
  }

  function fileMime(file) {
    return safeMimeHeader(file && file.type);
  }

  function fileSize(file) {
    return Number(file && file.size || 0) || 0;
  }

  function localFilePath(file) {
    var raw = file && (
      file.simplexFilePath ||
      file.simplex_file_path ||
      file.filePath ||
      file.path ||
      file.mozFullPath ||
      ''
    );
    var path = String(raw || '').trim();
    if (!path) return '';
    if (isAbsoluteLocalPath(path)) return path;
    return '';
  }

  function receiptAttachment(file, filePath) {
    return {
      name: fileName(file),
      mime: fileMime(file),
      size: fileSize(file),
      file_path: limitString(filePath || '', MAX_TEXT_LENGTH),
      data_url: limitString(file && (file.data_url || file.dataUrl || file.simplexPreviewUrl) || '', MAX_ATTACHMENT_DATA_URL_LENGTH)
    };
  }

  function stageFileWithBridge(config, file) {
    if (!config.file_bridge_url) {
      return Promise.reject(makeError(
        ERROR_CONFIG,
        'SimpleX file sending needs a loopback simplex-web file bridge because browsers do not expose local file paths'
      ));
    }
    var fetchImpl = config.fetchImpl || global.fetch;
    if (fetchImpl === global.fetch && typeof fetchImpl === 'function' && global) {
      fetchImpl = fetchImpl.bind(global);
    }
    if (typeof fetchImpl !== 'function') {
      return Promise.reject(makeError(ERROR_CONFIG, 'Browser fetch runtime is unavailable for SimpleX file staging'));
    }
    var requestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': fileMime(file),
        'X-File-Name': encodeURIComponent(fileName(file))
      },
      body: file
    };
    var timeoutId = null;
    if (global.AbortController && typeof global.AbortController === 'function' && config.timeout_ms) {
      var controller = new global.AbortController();
      requestOptions.signal = controller.signal;
      timeoutId = global.setTimeout(function () {
        controller.abort();
      }, config.timeout_ms);
    }
    var fetchPromise;
    try {
      fetchPromise = Promise.resolve(fetchImpl(config.file_bridge_url + '/files', requestOptions));
    } catch (error) {
      if (timeoutId) global.clearTimeout(timeoutId);
      return Promise.reject(error);
    }
    return fetchPromise.then(function (resp) {
      if (timeoutId) {
        global.clearTimeout(timeoutId);
        timeoutId = null;
      }
      if (!resp || resp.ok === false) {
        throw makeError(ERROR_RESPONSE, 'SimpleX file bridge rejected the attachment');
      }
      if (typeof resp.json === 'function') {
        return resp.json();
      }
      if (typeof resp.text === 'function') {
        return resp.text().then(function (text) {
          return JSON.parse(text);
        });
      }
      return resp;
    }, function (error) {
      if (timeoutId) global.clearTimeout(timeoutId);
      throw error;
    }).then(function (data) {
      var stagedPath = String(data && (data.filePath || data.file_path || data.path) || '').trim();
      if (!stagedPath) {
        throw makeError(ERROR_RESPONSE, 'SimpleX file bridge did not return a local file path');
      }
      if (!isAbsoluteLocalPath(stagedPath)) {
        throw makeError(ERROR_RESPONSE, 'SimpleX file bridge returned a non-absolute local file path');
      }
      return stagedPath;
    });
  }

  function filePathForSend(config, file) {
    var path = localFilePath(file);
    if (path) return Promise.resolve(path);
    return stageFileWithBridge(config, file);
  }

  function fileComposedMessage(filePath, caption) {
    return {
      fileSource: { filePath: filePath },
      msgContent: {
        type: 'file',
        text: limitString(caption || '', MAX_TEXT_LENGTH)
      },
      mentions: {}
    };
  }

  function fileSendCommand(contactId, filePath, caption) {
    return '/_send @' + normalizeCommandAtom(contactId, 'contact id', false) + ' json ' + JSON.stringify([
      fileComposedMessage(filePath, caption)
    ]);
  }

  function textSendCommand(contactId, text) {
    return '/_send @' + normalizeCommandAtom(contactId, 'contact id', false) + ' json ' + JSON.stringify([
      textComposedMessage(text)
    ]);
  }

  function createSimplexChatWebSocketAdapter(options) {
    var config = normalizeConfig(options);
    if (!config.WebSocketImpl) {
      throw makeError(ERROR_CONFIG, 'Browser WebSocket runtime is unavailable');
    }

    function sendText(message) {
      var payload = message && typeof message === 'object' ? message : {};
      var userId;
      var contactId;
      var contactLink;
      var text = limitString(payload.text || '', MAX_TEXT_LENGTH);
      try {
        userId = normalizeCommandAtom(payload.user_id || payload.userId || payload.bridge_user_id || payload.bridgeUserId || config.user_id || '', 'user id', true);
        contactId = normalizeCommandAtom(payload.contact_id || payload.contactId || payload.simplex_contact_id || '', 'contact id', true);
        contactLink = normalizeContactLink(payload.contact_link || payload.contactLink || payload.owner_contact_link || payload.ownerContactLink || '', true);
      } catch (error) {
        return Promise.reject(error);
      }
      if (!contactId && !contactLink) {
        return Promise.reject(makeError(ERROR_CONFIG, 'SimpleX Chat contact id or contact link is required'));
      }
      if (!text.trim()) {
        return Promise.reject(makeError('SIMPLEX_CHAT_WS_EMPTY_MESSAGE', 'message text is required'));
      }
      return sendTextSequential(config, payload, userId, contactId, contactLink, text, payload.client_message_id || payload.clientMessageId || '');
    }

    function getMessageStatus(message) {
      var payload = message && typeof message === 'object' ? message : {};
      var userId;
      var contactId;
      var contactLink;
      var messageRef = limitString(payload.message_ref || payload.messageRef || '', MAX_LABEL_LENGTH).trim();
      try {
        userId = normalizeCommandAtom(payload.user_id || payload.userId || payload.bridge_user_id || payload.bridgeUserId || config.user_id || '', 'user id', true);
        contactId = normalizeCommandAtom(payload.contact_id || payload.contactId || payload.simplex_contact_id || '', 'contact id', true);
        contactLink = normalizeContactLink(payload.contact_link || payload.contactLink || payload.owner_contact_link || payload.ownerContactLink || '', true);
      } catch (error) {
        return Promise.reject(error);
      }
      if (!contactId && !contactLink) {
        return Promise.reject(makeError(ERROR_CONFIG, 'SimpleX Chat contact id or contact link is required'));
      }
      if (!messageRef) {
        return Promise.reject(makeError(ERROR_CONFIG, 'SimpleX Chat message ref is required'));
      }
      return queryMessageStatusSequential(config, payload, userId, contactId, contactLink, messageRef);
    }

    function getMessages(message) {
      var payload = message && typeof message === 'object' ? message : {};
      var userId;
      var contactId;
      var contactLink;
      var count = Math.max(1, Math.min(200, Math.floor(Number(payload.limit || payload.count || 50) || 50)));
      try {
        userId = normalizeCommandAtom(payload.user_id || payload.userId || payload.bridge_user_id || payload.bridgeUserId || config.user_id || '', 'user id', true);
        contactId = normalizeCommandAtom(payload.contact_id || payload.contactId || payload.simplex_contact_id || '', 'contact id', true);
        contactLink = normalizeContactLink(payload.contact_link || payload.contactLink || payload.owner_contact_link || payload.ownerContactLink || '', true);
      } catch (error) {
        return Promise.reject(error);
      }
      if (!contactId && !contactLink) {
        return Promise.reject(makeError(ERROR_CONFIG, 'SimpleX Chat contact id or contact link is required'));
      }
      return queryMessagesSequential(config, payload, userId, contactId, contactLink, count);
    }

    function sendFiles(message) {
      var payload = message && typeof message === 'object' ? message : {};
      var userId;
      var contactId;
      var contactLink;
      var files = Array.prototype.slice.call(payload.files || []).filter(Boolean);
      var maxBytes = Math.max(1, Number(payload.max_file_bytes || 12000) || 12000);
      try {
        userId = normalizeCommandAtom(payload.user_id || payload.userId || payload.bridge_user_id || payload.bridgeUserId || config.user_id || '', 'user id', true);
        contactId = normalizeCommandAtom(payload.contact_id || payload.contactId || payload.simplex_contact_id || '', 'contact id', true);
        contactLink = normalizeContactLink(payload.contact_link || payload.contactLink || payload.owner_contact_link || payload.ownerContactLink || '', true);
      } catch (error) {
        return Promise.reject(error);
      }
      if (!contactId && !contactLink) {
        return Promise.reject(makeError(ERROR_CONFIG, 'SimpleX Chat contact id or contact link is required'));
      }
      if (!files.length) {
        return Promise.reject(makeError(ERROR_CONFIG, 'at least one file is required'));
      }
      return files.reduce(function (promise, file) {
        return promise.then(function (receipts) {
          if (Number(file.size || 0) > maxBytes) {
            throw makeError(ERROR_CONFIG, 'Secure Chat attachments are limited to ' + String(maxBytes) + ' bytes for browser-local SimpleX sends');
          }
          return filePathForSend(config, file).then(function (stagedPath) {
            return sendTextSequential(
              config,
              payload,
              userId,
              contactId,
              contactLink,
              payload.text || '',
              payload.client_message_id || payload.clientMessageId || '',
              function (resolvedContactId) {
                return fileSendCommand(resolvedContactId, stagedPath, payload.text || '');
              }
            ).then(function (receipt) {
              receipts.push(Object.assign({}, receipt, {
                attachment: receiptAttachment(file, stagedPath)
              }));
              return receipts;
            });
          });
        });
      }, Promise.resolve([]));
    }

    return {
      getStatus: function () {
        return {
          transport_status: 'simplex-chat-websocket',
          transport_error: '',
          file_bridge_url: config.file_bridge_url
        };
      },
      connect: function () {
        return Promise.resolve(this.getStatus());
      },
      sendText: sendText,
      sendFiles: sendFiles,
      getMessageStatus: getMessageStatus,
      getMessages: getMessages,
      disconnect: function () {
        return Promise.resolve();
      }
    };
  }

  function sendTextSequential(config, payload, userId, contactId, contactLink, text, clientMessageId, sendCommandForContact) {
    return new Promise(function (resolve, reject) {
      var WebSocketImpl = config.WebSocketImpl;
      var ws = null;
      var settled = false;
      var resolved = false;
      var step = 0;
      var sendAttempts = 0;
      var commandSeq = 0;
      var reconnectedAfterSendError = false;
      var pendingCorrId = '';
      var statusPollCorrId = '';
      var statusPollTimer = null;
      var statusPollInFlight = false;
      var sentMessageRef = '';
      var statusTimer = null;
      var timer = global.setTimeout(function () {
        finish(reject, makeError(ERROR_TIMEOUT, 'SimpleX Chat WebSocket command timed out'));
      }, config.timeout_ms);

      function closeSocket() {
        if (statusTimer) {
          global.clearTimeout(statusTimer);
          statusTimer = null;
        }
        if (statusPollTimer) {
          global.clearTimeout(statusPollTimer);
          statusPollTimer = null;
        }
        if (ws) {
          try { ws.close(); } catch (_err) {}
          ws = null;
        }
      }

      function finish(fn, value) {
        if (settled) return;
        settled = true;
        global.clearTimeout(timer);
        closeSocket();
        fn(value);
      }

      function resolveInitial(receipt, keepListening) {
        if (resolved) return;
        resolved = true;
        global.clearTimeout(timer);
        resolve(receipt);
        if (!keepListening) {
          settled = true;
          closeSocket();
        }
      }

      function stopStatusWatch() {
        settled = true;
        closeSocket();
      }

      function scheduleStatusPoll(delay) {
        if (settled || !sentMessageRef || !contactId) return;
        if (statusPollTimer) {
          global.clearTimeout(statusPollTimer);
        }
        statusPollTimer = global.setTimeout(function () {
          statusPollTimer = null;
          if (settled || statusPollInFlight || !ws || !sentMessageRef || !contactId) return;
          statusPollInFlight = true;
          statusPollCorrId = send('/_get chat @' + contactId + ' count=20');
        }, delay);
      }

      function handleStatusReceipt(statusReceipt) {
        emitStatus(payload, statusReceipt);
        if (statusIsTerminal(statusReceipt.transport_status)) {
          stopStatusWatch();
        } else {
          scheduleStatusPoll(350);
        }
      }

      function send(cmd) {
        var corrId = 'sxw-' + Date.now() + '-' + (++commandSeq);
        pendingCorrId = corrId;
        try {
          ws.send(JSON.stringify({ corrId: corrId, cmd: cmd }));
        } catch (error) {
          finish(reject, error);
          return '';
        }
        return corrId;
      }

      function sendMessageToContact(resolvedContactId) {
        var safeContactId;
        var command;
        try {
          safeContactId = normalizeCommandAtom(resolvedContactId, 'contact id', false);
          command = typeof sendCommandForContact === 'function'
            ? sendCommandForContact(safeContactId)
            : textSendCommand(safeContactId, text);
        } catch (error) {
          finish(reject, error);
          return;
        }
        send(command);
      }

      function onOpen() {
        if (userId) {
          send('/_user ' + userId);
        } else {
          send('/u');
        }
      }

      function onMessage(event) {
        var envelope = parseEnvelope(event && event.data);
        var resp = envelope && envelope.resp;
        var type = responseType(resp);
        if (!resp) return;
        var corrId = String(envelope.corrId || '');
        if (resolved) {
          if (type === 'chatItemsStatusesUpdated') {
            var statusChatItem = matchingStatusChatItem(resp, sentMessageRef);
            if (!statusChatItem) return;
            handleStatusReceipt(statusReceiptFromChatItem(statusChatItem, sentMessageRef || clientMessageId));
            return;
          }
          if (corrId && corrId === statusPollCorrId) {
            statusPollInFlight = false;
            statusPollCorrId = '';
            if (type === 'apiChat') {
              var polledChatItem = matchingStatusChatItem(resp, sentMessageRef);
              if (polledChatItem) {
                handleStatusReceipt(statusReceiptFromChatItem(polledChatItem, sentMessageRef || clientMessageId));
              } else {
                scheduleStatusPoll(500);
              }
            } else if (type === 'chatCmdError') {
              scheduleStatusPoll(800);
            }
          }
          return;
        }
        if (step === 0) {
          if (corrId && corrId !== pendingCorrId) {
            return;
          }
          if (!corrId && type !== 'activeUser') {
            return;
          }
          if (type !== 'activeUser') {
            finish(reject, makeError(ERROR_RESPONSE, 'Could not resolve SimpleX Chat active user: ' + (type || 'unknown')));
            return;
          }
          try {
            userId = userId || activeUserIdFromResponse(resp);
          } catch (error) {
            finish(reject, error);
            return;
          }
          if (!userId) {
            finish(reject, makeError(ERROR_RESPONSE, 'SimpleX Chat active user response did not include a user id'));
            return;
          }
          var cachedId = !contactId ? cachedContactId(config, payload, userId, contactLink) : '';
          contactId = contactId || cachedId;
          step = 1;
          if (contactId) {
            sendAttempts = 1;
            sendMessageToContact(contactId);
          } else {
            send('/connect ' + contactLink);
          }
          return;
        }
        if (step === 1 && !contactId) {
          if (type === 'contactAlreadyExists' || type === 'contactConnected' || type === 'contactConnecting' || type === 'connectionPlan') {
            try {
              contactId = contactIdFromResponse(resp);
            } catch (error) {
              finish(reject, error);
              return;
            }
            if (contactId) {
              rememberContactId(config, payload, userId, contactLink, contactId);
              step = 2;
              sendAttempts = 1;
              sendMessageToContact(contactId);
            }
            return;
          }
          if (type === 'sentConfirmation' || type === 'sentInvitation') {
            return;
          }
          if (type === 'chatCmdError') {
            var detail = chatErrorSummary(resp);
            finish(reject, makeError(ERROR_RESPONSE, 'Could not connect SimpleX contact link' + (detail ? ': ' + detail : '')));
          }
          return;
        }
        if (step === 1 && contactId) {
          step = 2;
        }
        if (type === 'newChatItems') {
          var chatItem = firstChatItem(resp);
          var receipt = statusReceiptFromChatItem(chatItem, clientMessageId);
          sentMessageRef = receipt.message_ref;
          var shouldWatchStatus = typeof payload.on_status === 'function' && !statusIsTerminal(receipt.transport_status);
          resolveInitial(receipt, shouldWatchStatus);
          if (shouldWatchStatus) {
            statusTimer = global.setTimeout(stopStatusWatch, config.status_timeout_ms);
            scheduleStatusPoll(200);
          }
          return;
        }
        if (type === 'chatCmdError' && contactLink && contactId && !reconnectedAfterSendError) {
          reconnectedAfterSendError = true;
          forgetContactId(config, payload, userId, contactLink);
          contactId = '';
          step = 1;
          sendAttempts = 0;
          send('/connect ' + contactLink);
          return;
        }
        if (type === 'chatCmdError' && sendAttempts < config.retries) {
          var errorType = chatErrorType(resp);
          sendAttempts += 1;
          global.setTimeout(function () {
            if (!settled) {
              sendMessageToContact(contactId);
            }
          }, errorType === 'contactNotReady'
            ? Math.min(config.retry_delay_ms * sendAttempts, 5000)
            : 150);
          return;
        }
        finish(reject, makeError(ERROR_RESPONSE, 'Unexpected SimpleX Chat response: ' + (type || 'unknown')));
      }

      function onError(event) {
        if (isPageLifecycleClosing()) {
          return;
        }
        finish(reject, makeError(ERROR_RESPONSE, event && event.message ? event.message : 'SimpleX Chat WebSocket failed'));
      }

      try {
        ws = new WebSocketImpl(config.url);
        ws.addEventListener('open', onOpen);
        ws.addEventListener('message', onMessage);
        ws.addEventListener('error', onError);
      } catch (error) {
        finish(reject, error);
      }
    });
  }

  function queryMessageStatusSequential(config, payload, userId, contactId, contactLink, messageRef) {
    return new Promise(function (resolve, reject) {
      var WebSocketImpl = config.WebSocketImpl;
      var ws = null;
      var settled = false;
      var step = 0;
      var commandSeq = 0;
      var pendingCorrId = '';
      var timer = global.setTimeout(function () {
        finish(reject, makeError(ERROR_TIMEOUT, 'SimpleX Chat WebSocket status query timed out'));
      }, config.timeout_ms);

      function closeSocket() {
        if (ws) {
          try { ws.close(); } catch (_err) {}
          ws = null;
        }
      }

      function finish(fn, value) {
        if (settled) return;
        settled = true;
        global.clearTimeout(timer);
        closeSocket();
        fn(value);
      }

      function send(cmd) {
        var corrId = 'sxw-' + Date.now() + '-' + (++commandSeq);
        pendingCorrId = corrId;
        try {
          ws.send(JSON.stringify({ corrId: corrId, cmd: cmd }));
        } catch (error) {
          finish(reject, error);
        }
      }

      function onOpen() {
        if (userId) {
          send('/_user ' + userId);
        } else {
          send('/u');
        }
      }

      function onMessage(event) {
        var envelope = parseEnvelope(event && event.data);
        var resp = envelope && envelope.resp;
        var type = responseType(resp);
        if (!resp) return;
        var corrId = String(envelope.corrId || '');
        if (step === 0) {
          if (corrId && corrId !== pendingCorrId) {
            return;
          }
          if (!corrId && type !== 'activeUser') {
            return;
          }
          if (type !== 'activeUser') {
            finish(reject, makeError(ERROR_RESPONSE, 'Could not resolve SimpleX Chat active user: ' + (type || 'unknown')));
            return;
          }
          try {
            userId = userId || activeUserIdFromResponse(resp);
          } catch (error) {
            finish(reject, error);
            return;
          }
          if (!userId) {
            finish(reject, makeError(ERROR_RESPONSE, 'SimpleX Chat active user response did not include a user id'));
            return;
          }
          contactId = contactId || cachedContactId(config, payload, userId, contactLink);
          if (!contactId) {
            finish(resolve, {
              accepted: true,
              transport_status: 'unknown',
              raw_status: '',
              message_ref: messageRef,
              chat_item: null
            });
            return;
          }
          step = 1;
          send('/_get chat @' + contactId + ' count=20');
          return;
        }
        if (step === 1) {
          if (corrId && corrId !== pendingCorrId) {
            return;
          }
          if (!corrId && type !== 'apiChat' && type !== 'chatCmdError') {
            return;
          }
          if (type === 'apiChat') {
            var chatItem = matchingStatusChatItem(resp, messageRef);
            finish(resolve, chatItem
              ? statusReceiptFromChatItem(chatItem, messageRef)
              : {
                accepted: true,
                transport_status: 'unknown',
                raw_status: '',
                message_ref: messageRef,
                chat_item: null
              });
            return;
          }
          if (type === 'chatCmdError') {
            finish(reject, makeError(ERROR_RESPONSE, chatErrorSummary(resp) || 'Could not query SimpleX Chat message status'));
            return;
          }
          finish(reject, makeError(ERROR_RESPONSE, 'Unexpected SimpleX Chat status response: ' + (type || 'unknown')));
        }
      }

      function onError(event) {
        if (isPageLifecycleClosing()) {
          return;
        }
        finish(reject, makeError(ERROR_RESPONSE, event && event.message ? event.message : 'SimpleX Chat WebSocket failed'));
      }

      try {
        ws = new WebSocketImpl(config.url);
        ws.addEventListener('open', onOpen);
        ws.addEventListener('message', onMessage);
        ws.addEventListener('error', onError);
      } catch (error) {
        finish(reject, error);
      }
    });
  }

  function queryMessagesSequential(config, payload, userId, contactId, contactLink, count) {
    return new Promise(function (resolve, reject) {
      var WebSocketImpl = config.WebSocketImpl;
      var ws = null;
      var settled = false;
      var step = 0;
      var commandSeq = 0;
      var pendingCorrId = '';
      var receiveQueue = [];
      var receiveIndex = 0;
      var receivePasses = 0;
      var timer = global.setTimeout(function () {
        finish(reject, makeError(ERROR_TIMEOUT, 'SimpleX Chat WebSocket receive query timed out'));
      }, config.timeout_ms);

      function closeSocket() {
        if (ws) {
          try { ws.close(); } catch (_err) {}
          ws = null;
        }
      }

      function finish(fn, value) {
        if (settled) return;
        settled = true;
        global.clearTimeout(timer);
        closeSocket();
        fn(value);
      }

      function send(cmd) {
        var corrId = 'sxw-' + Date.now() + '-' + (++commandSeq);
        pendingCorrId = corrId;
        try {
          ws.send(JSON.stringify({ corrId: corrId, cmd: cmd }));
        } catch (error) {
          finish(reject, error);
        }
      }

      function normalizedMessages(items) {
        return items.map(function (item) {
          return messageFromChatItem(config, item);
        }).filter(function (message) {
          return !!(message.message_ref && (String(message.text || '').trim() || message.attachment));
        });
      }

      function scheduleChatRequery() {
        global.setTimeout(function () {
          if (!settled) {
            step = 1;
            send('/_get chat @' + contactId + ' count=' + String(count));
          }
        }, config.receive_requery_delay_ms);
      }

      function receiveNextFile() {
        if (receiveIndex >= receiveQueue.length) {
          scheduleChatRequery();
          return;
        }
        var file = receiveQueue[receiveIndex] && receiveQueue[receiveIndex].file;
        receiveIndex += 1;
        send('/freceive ' + chatFileId(file));
      }

      function onOpen() {
        if (userId) {
          send('/_user ' + userId);
        } else {
          send('/u');
        }
      }

      function onMessage(event) {
        var envelope = parseEnvelope(event && event.data);
        var resp = envelope && envelope.resp;
        var type = responseType(resp);
        if (!resp) return;
        var corrId = String(envelope.corrId || '');
        if (step === 0) {
          if (corrId && corrId !== pendingCorrId) {
            return;
          }
          if (!corrId && type !== 'activeUser') {
            return;
          }
          if (type !== 'activeUser') {
            finish(reject, makeError(ERROR_RESPONSE, 'Could not resolve SimpleX Chat active user: ' + (type || 'unknown')));
            return;
          }
          try {
            userId = userId || activeUserIdFromResponse(resp);
          } catch (error) {
            finish(reject, error);
            return;
          }
          if (!userId) {
            finish(reject, makeError(ERROR_RESPONSE, 'SimpleX Chat active user response did not include a user id'));
            return;
          }
          contactId = contactId || cachedContactId(config, payload, userId, contactLink);
          if (!contactId) {
            finish(resolve, []);
            return;
          }
          step = 1;
          send('/_get chat @' + contactId + ' count=' + String(count));
          return;
        }
        if (step === 1) {
          if (corrId && corrId !== pendingCorrId) {
            return;
          }
          if (!corrId && type !== 'apiChat' && type !== 'chatCmdError') {
            return;
          }
          if (type === 'apiChat') {
            var items = responseChatItems(resp);
            var needsReceive = items.filter(function (item) {
              return chatItemNeedsFileReceive(config, item);
            });
            var pendingReceive = items.filter(function (item) {
              return chatItemHasPendingFileReceive(config, item);
            });
            if ((needsReceive.length || pendingReceive.length) && receivePasses < 6) {
              receivePasses += 1;
              if (needsReceive.length) {
                receiveQueue = needsReceive;
                receiveIndex = 0;
                step = 2;
                receiveNextFile();
              } else {
                scheduleChatRequery();
              }
              return;
            }
            finish(resolve, normalizedMessages(items));
            return;
          }
          if (type === 'chatCmdError') {
            finish(reject, makeError(ERROR_RESPONSE, chatErrorSummary(resp) || 'Could not query SimpleX Chat messages'));
            return;
          }
          finish(reject, makeError(ERROR_RESPONSE, 'Unexpected SimpleX Chat receive response: ' + (type || 'unknown')));
          return;
        }
        if (step === 2) {
          if (corrId && corrId !== pendingCorrId) {
            return;
          }
          if (!corrId) {
            return;
          }
          if (type === 'rcvFileAccepted' || type === 'chatCmdError') {
            receiveNextFile();
            return;
          }
          receiveNextFile();
        }
      }

      function onError(event) {
        if (isPageLifecycleClosing()) {
          return;
        }
        finish(reject, makeError(ERROR_RESPONSE, event && event.message ? event.message : 'SimpleX Chat WebSocket failed'));
      }

      try {
        ws = new WebSocketImpl(config.url);
        ws.addEventListener('open', onOpen);
        ws.addEventListener('message', onMessage);
        ws.addEventListener('error', onError);
      } catch (error) {
        finish(reject, error);
      }
    });
  }

  function registerSimplexChatWebSocketTransport(options) {
    var transportApi = global.SimplexWebTransport;
    if (!transportApi || typeof transportApi.registerBrowserTransport !== 'function') {
      throw makeError(ERROR_CONFIG, 'SimplexWebTransport facade must be loaded before the WebSocket adapter');
    }
    return transportApi.registerBrowserTransport(createSimplexChatWebSocketAdapter(options));
  }

  var api = {
    ERROR_CONFIG: ERROR_CONFIG,
    ERROR_TIMEOUT: ERROR_TIMEOUT,
    ERROR_RESPONSE: ERROR_RESPONSE,
    ERROR_SECURITY: ERROR_SECURITY,
    createSimplexChatWebSocketAdapter: createSimplexChatWebSocketAdapter,
    registerSimplexChatWebSocketTransport: registerSimplexChatWebSocketTransport
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  global.SimplexChatWebSocketAdapter = api;

  if (global.SimplexWebSocketAdapterConfig) {
    registerSimplexChatWebSocketTransport(global.SimplexWebSocketAdapterConfig);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
