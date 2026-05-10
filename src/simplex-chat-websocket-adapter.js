(function (global) {
  'use strict';

  var MAX_TEXT_LENGTH = 4000;
  var MAX_LABEL_LENGTH = 256;
  var DEFAULT_TIMEOUT_MS = 90000;
  var DEFAULT_RETRIES = 3;
  var ERROR_CONFIG = 'SIMPLEX_CHAT_WS_CONFIG';
  var ERROR_TIMEOUT = 'SIMPLEX_CHAT_WS_TIMEOUT';
  var ERROR_RESPONSE = 'SIMPLEX_CHAT_WS_RESPONSE';
  var ERROR_SECURITY = 'SIMPLEX_CHAT_WS_SECURITY';
  var STORAGE_PREFIX = 'simplex-chat-websocket-adapter-v1';

  function limitString(value, maxLength) {
    return String(value == null ? '' : value).slice(0, maxLength);
  }

  function makeError(code, message) {
    var error = new Error(message);
    error.name = 'SimplexChatWebSocketAdapterError';
    error.code = code;
    return error;
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

  function normalizeConfig(options) {
    var opts = options && typeof options === 'object' ? options : {};
    var url = normalizeUrl(opts.url || opts.webSocketUrl || opts.websocketUrl || opts.endpoint || '');
    var userId = limitString(opts.user_id || opts.userId || opts.active_user_id || opts.activeUserId || '', MAX_LABEL_LENGTH).trim();
    return {
      url: validateWebSocketUrl(url, opts.allowRemote === true),
      user_id: userId,
      timeout_ms: Math.max(1000, Math.floor(Number(opts.timeout_ms || opts.timeoutMs || DEFAULT_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS)),
      retries: Math.max(1, Math.floor(Number(opts.retries || DEFAULT_RETRIES) || DEFAULT_RETRIES)),
      storage: opts.storage || null,
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
    var text = String(id == null ? '' : id).replace(/^@/, '').trim();
    return text ? limitString(text, MAX_LABEL_LENGTH) : '';
  }

  function activeUserIdFromResponse(resp) {
    var user = resp && (resp.user || resp.currentUser || resp.activeUser || resp);
    var id = user && (user.userId || user.user_id || user.id);
    var text = String(id == null ? '' : id).trim();
    return text ? limitString(text, MAX_LABEL_LENGTH) : '';
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
      return limitString(storage.getItem(cacheKey(payload, userId, contactLink)) || '', MAX_LABEL_LENGTH).replace(/^@/, '').trim();
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

  function encodeTextCommand(text) {
    return String(text || '').replace(/\r\n/g, '\n');
  }

  function createSimplexChatWebSocketAdapter(options) {
    var config = normalizeConfig(options);
    if (!config.WebSocketImpl) {
      throw makeError(ERROR_CONFIG, 'Browser WebSocket runtime is unavailable');
    }

    function sendText(message) {
      var payload = message && typeof message === 'object' ? message : {};
      var userId = limitString(payload.user_id || payload.userId || payload.bridge_user_id || payload.bridgeUserId || config.user_id || '', MAX_LABEL_LENGTH).trim();
      var contactId = limitString(payload.contact_id || payload.contactId || payload.simplex_contact_id || '', MAX_LABEL_LENGTH).trim();
      var contactLink = limitString(payload.contact_link || payload.contactLink || payload.owner_contact_link || payload.ownerContactLink || '', MAX_TEXT_LENGTH).trim();
      var text = limitString(payload.text || '', MAX_TEXT_LENGTH);
      if (!contactId && !contactLink) {
        return Promise.reject(makeError(ERROR_CONFIG, 'SimpleX Chat contact id or contact link is required'));
      }
      if (!text.trim()) {
        return Promise.reject(makeError('SIMPLEX_CHAT_WS_EMPTY_MESSAGE', 'message text is required'));
      }
      return sendTextSequential(config, payload, userId, contactId, contactLink, text, payload.client_message_id || payload.clientMessageId || '');
    }

    return {
      getStatus: function () {
        return {
          transport_status: 'simplex-chat-websocket',
          transport_error: ''
        };
      },
      connect: function () {
        return Promise.resolve(this.getStatus());
      },
      sendText: sendText,
      disconnect: function () {
        return Promise.resolve();
      }
    };
  }

  function sendTextSequential(config, payload, userId, contactId, contactLink, text, clientMessageId) {
    return new Promise(function (resolve, reject) {
      var WebSocketImpl = config.WebSocketImpl;
      var ws = null;
      var settled = false;
      var step = 0;
      var sendAttempts = 0;
      var commandSeq = 0;
      var pendingCorrId = '';
      var timer = global.setTimeout(function () {
        finish(reject, makeError(ERROR_TIMEOUT, 'SimpleX Chat WebSocket command timed out'));
      }, config.timeout_ms);

      function finish(fn, value) {
        if (settled) return;
        settled = true;
        global.clearTimeout(timer);
        if (ws) {
          try { ws.close(); } catch (_err) {}
        }
        fn(value);
      }

      function send(cmd) {
        var corrId = 'sxw-' + Date.now() + '-' + (++commandSeq);
        pendingCorrId = corrId;
        ws.send(JSON.stringify({ corrId: corrId, cmd: cmd }));
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
          userId = userId || activeUserIdFromResponse(resp);
          if (!userId) {
            finish(reject, makeError(ERROR_RESPONSE, 'SimpleX Chat active user response did not include a user id'));
            return;
          }
          contactId = contactId || cachedContactId(config, payload, userId, contactLink);
          step = 1;
          if (contactId) {
            sendAttempts = 1;
            send('/_send @' + contactId + ' text ' + encodeTextCommand(text));
          } else {
            send('/connect ' + contactLink);
          }
          return;
        }
        if (step === 1 && !contactId) {
          if (type === 'contactAlreadyExists' || type === 'contactConnected' || type === 'contactConnecting' || type === 'connectionPlan') {
            contactId = contactIdFromResponse(resp);
            if (contactId) {
              rememberContactId(config, payload, userId, contactLink, contactId);
              step = 2;
              sendAttempts = 1;
              send('/_send @' + contactId + ' text ' + encodeTextCommand(text));
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
          finish(resolve, {
            accepted: true,
            transport_status: chatItemStatus(chatItem),
            message_ref: limitString(chatItem && chatItem.meta && chatItem.meta.itemId != null ? String(chatItem.meta.itemId) : clientMessageId, MAX_LABEL_LENGTH),
            chat_item: chatItem || null
          });
          return;
        }
        if (type === 'chatCmdError' && sendAttempts < config.retries) {
          sendAttempts += 1;
          global.setTimeout(function () {
            if (!settled) {
              send('/_send @' + contactId + ' text ' + encodeTextCommand(text));
            }
          }, 150);
          return;
        }
        finish(reject, makeError(ERROR_RESPONSE, 'Unexpected SimpleX Chat response: ' + (type || 'unknown')));
      }

      function onError(event) {
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
