(function (global) {
  'use strict';

  var MAX_TEXT_LENGTH = 4000;
  var MAX_LABEL_LENGTH = 256;
  var MAX_STATUS_LENGTH = 64;
  var UNAVAILABLE_STATUS = 'browser-native-unavailable';
  var UNAVAILABLE_MESSAGE = 'browser-native simplex-web transport is not available';
  var ERROR_UNAVAILABLE = 'SIMPLEX_WEB_TRANSPORT_UNAVAILABLE';
  var ERROR_BAD_ADAPTER = 'SIMPLEX_WEB_TRANSPORT_BAD_ADAPTER';
  var MAX_FILE_BYTES = 12000;

  function limitString(value, maxLength) {
    return String(value == null ? '' : value).slice(0, maxLength);
  }

  function normalizeStatus(value, fallback) {
    var status = limitString(value || fallback || '', MAX_STATUS_LENGTH).trim();
    return status || fallback || UNAVAILABLE_STATUS;
  }

  function makeTransportError(code, message) {
    var error = new Error(message || UNAVAILABLE_MESSAGE);
    error.name = 'SimplexWebTransportError';
    error.code = code || ERROR_UNAVAILABLE;
    return error;
  }

  function normalizeOutboundMessage(message, options) {
    var opts = options && typeof options === 'object' ? options : {};
    var payload = message && typeof message === 'object' && !Array.isArray(message)
      ? message
      : { text: message };

    return {
      contact_id: limitString(payload.contact_id || payload.contactId || opts.contact_id || opts.contactId || '', MAX_LABEL_LENGTH),
      contact_link: limitString(payload.contact_link || payload.contactLink || payload.owner_contact_link || payload.ownerContactLink || opts.contact_link || opts.contactLink || opts.owner_contact_link || opts.ownerContactLink || '', MAX_TEXT_LENGTH),
      text: limitString(payload.text || '', MAX_TEXT_LENGTH),
      client_message_id: limitString(payload.client_message_id || payload.clientMessageId || opts.client_message_id || opts.clientMessageId || '', MAX_LABEL_LENGTH),
      message_ref: limitString(payload.message_ref || payload.messageRef || opts.message_ref || opts.messageRef || '', MAX_LABEL_LENGTH),
      user_id: limitString(payload.user_id || payload.userId || payload.bridge_user_id || payload.bridgeUserId || opts.user_id || opts.userId || opts.bridge_user_id || opts.bridgeUserId || '', MAX_LABEL_LENGTH),
      on_status: typeof payload.on_status === 'function'
        ? payload.on_status
        : (typeof payload.onStatus === 'function' ? payload.onStatus : null)
    };
  }

  function normalizeMessageQuery(message, options) {
    var normalized = normalizeOutboundMessage(message, options);
    var limit = Math.max(1, Math.min(200, Math.floor(Number(
      (message && (message.limit || message.count)) ||
      (options && (options.limit || options.count)) ||
      50
    ) || 50)));
    normalized.limit = limit;
    return normalized;
  }

  function normalizeReceipt(value, fallbackMessage) {
    var next = value && typeof value === 'object' ? value : {};
    return {
      accepted: next.accepted !== false,
      transport_status: normalizeStatus(next.transport_status || next.transportStatus, 'accepted'),
      message_ref: limitString(next.message_ref || next.messageRef || fallbackMessage.message_ref || fallbackMessage.client_message_id || '', MAX_LABEL_LENGTH)
    };
  }

  function normalizeIncomingMessage(value) {
    var next = value && typeof value === 'object' ? value : {};
    var direction = String(next.direction || '').trim().toLowerCase() === 'incoming' ? 'incoming' : 'outgoing';
    return {
      seq: 0,
      direction: direction,
      message_ref: limitString(next.message_ref || next.messageRef || '', MAX_LABEL_LENGTH),
      message_kind: limitString(next.message_kind || next.messageKind || 'text', MAX_STATUS_LENGTH) || 'text',
      delivery_status: normalizeStatus(next.delivery_status || next.deliveryStatus || next.transport_status || next.transportStatus, direction === 'incoming' ? 'received' : 'sent'),
      created_at: limitString(next.created_at || next.createdAt || '', MAX_TEXT_LENGTH),
      updated_at: limitString(next.updated_at || next.updatedAt || '', MAX_TEXT_LENGTH),
      text: limitString(next.text || '', MAX_TEXT_LENGTH),
      attachment: next.attachment && typeof next.attachment === 'object'
        ? {
          name: limitString(next.attachment.name || '', MAX_TEXT_LENGTH),
          mime: limitString(next.attachment.mime || '', MAX_STATUS_LENGTH),
          size: Number(next.attachment.size || 0) || 0
        }
        : null
    };
  }

  function normalizeFileList(files) {
    return Array.prototype.slice.call(files || []).filter(function (file) {
      return !!(file && typeof file === 'object' && typeof file.name === 'string');
    });
  }

  function unavailableSnapshot(reason) {
    return {
      available: false,
      transport_status: UNAVAILABLE_STATUS,
      transport_error: limitString(reason || UNAVAILABLE_MESSAGE, MAX_TEXT_LENGTH)
    };
  }

  function validateAdapter(adapter) {
    return !!(adapter && typeof adapter === 'object' && typeof adapter.sendText === 'function');
  }

  function createTransport(adapter, options) {
    var opts = options && typeof options === 'object' ? options : {};
    var activeAdapter = validateAdapter(adapter) ? adapter : null;
    var unavailableReason = limitString(opts.unavailableReason || UNAVAILABLE_MESSAGE, MAX_TEXT_LENGTH);

    function requireAdapter() {
      if (!activeAdapter) {
        throw makeTransportError(ERROR_UNAVAILABLE, unavailableReason);
      }
      return activeAdapter;
    }

    function getStatus() {
      if (!activeAdapter) {
        return unavailableSnapshot(unavailableReason);
      }
      if (typeof activeAdapter.getStatus === 'function') {
        var reported = activeAdapter.getStatus() || {};
        return {
          available: true,
          transport_status: normalizeStatus(reported.transport_status || reported.transportStatus, 'connected'),
          transport_error: limitString(reported.transport_error || reported.transportError || '', MAX_TEXT_LENGTH)
        };
      }
      return {
        available: true,
        transport_status: 'connected',
        transport_error: ''
      };
    }

    return {
      isAvailable: function () {
        return !!activeAdapter;
      },
      getStatus: getStatus,
      connect: function (params) {
        var target;
        try {
          target = requireAdapter();
        } catch (error) {
          return Promise.reject(error);
        }
        if (typeof target.connect === 'function') {
          return Promise.resolve(target.connect(params && typeof params === 'object' ? params : {}));
        }
        return Promise.resolve(getStatus());
      },
      sendText: function (message, options) {
        var target;
        try {
          target = requireAdapter();
        } catch (error) {
          return Promise.reject(error);
        }
        var normalized = normalizeOutboundMessage(message, options);
        if (!normalized.text.trim()) {
          return Promise.reject(makeTransportError('SIMPLEX_WEB_TRANSPORT_EMPTY_MESSAGE', 'message text is required'));
        }
        return Promise.resolve(target.sendText(normalized)).then(function (receipt) {
          return normalizeReceipt(receipt, normalized);
        });
      },
      sendFiles: function (message, options) {
        var target;
        try {
          target = requireAdapter();
        } catch (error) {
          return Promise.reject(error);
        }
        if (typeof target.sendFiles !== 'function') {
          return Promise.reject(makeTransportError('SIMPLEX_WEB_TRANSPORT_FILES_UNAVAILABLE', 'file sending is not available in this browser SimpleX transport'));
        }
        var normalized = normalizeOutboundMessage(message, options);
        var files = normalizeFileList((message && message.files) || (options && options.files) || []);
        if (!files.length) {
          return Promise.reject(makeTransportError('SIMPLEX_WEB_TRANSPORT_EMPTY_FILES', 'at least one file is required'));
        }
        return Promise.resolve(target.sendFiles(Object.assign({}, normalized, {
          files: files,
          max_file_bytes: MAX_FILE_BYTES
        })));
      },
      getMessageStatus: function (message, options) {
        var target;
        try {
          target = requireAdapter();
        } catch (error) {
          return Promise.reject(error);
        }
        if (typeof target.getMessageStatus !== 'function') {
          return Promise.reject(makeTransportError('SIMPLEX_WEB_TRANSPORT_STATUS_UNAVAILABLE', 'message status lookup is not available'));
        }
        var normalized = normalizeOutboundMessage(message, options);
        if (!normalized.message_ref) {
          return Promise.reject(makeTransportError('SIMPLEX_WEB_TRANSPORT_EMPTY_MESSAGE_REF', 'message ref is required'));
        }
        return Promise.resolve(target.getMessageStatus(normalized)).then(function (receipt) {
          return normalizeReceipt(receipt, normalized);
        });
      },
      getMessages: function (message, options) {
        var target;
        try {
          target = requireAdapter();
        } catch (error) {
          return Promise.reject(error);
        }
        if (typeof target.getMessages !== 'function') {
          return Promise.reject(makeTransportError('SIMPLEX_WEB_TRANSPORT_RECEIVE_UNAVAILABLE', 'message receive lookup is not available'));
        }
        var normalized = normalizeMessageQuery(message, options);
        return Promise.resolve(target.getMessages(normalized)).then(function (messages) {
          return (Array.isArray(messages) ? messages : []).map(normalizeIncomingMessage);
        });
      },
      disconnect: function () {
        var target;
        try {
          target = requireAdapter();
        } catch (error) {
          return Promise.reject(error);
        }
        if (typeof target.disconnect === 'function') {
          return Promise.resolve(target.disconnect());
        }
        return Promise.resolve();
      }
    };
  }

  function createUnavailableTransport(reason) {
    return createTransport(null, { unavailableReason: reason || UNAVAILABLE_MESSAGE });
  }

  function registerBrowserTransport(adapter) {
    if (!validateAdapter(adapter)) {
      throw makeTransportError(ERROR_BAD_ADAPTER, 'browser-native transport adapter must expose sendText(message)');
    }
    var transport = createTransport(adapter);
    global.SimplexWebTransport = transport;
    return transport;
  }

  var api = createUnavailableTransport();
  api.MAX_TEXT_LENGTH = MAX_TEXT_LENGTH;
  api.MAX_LABEL_LENGTH = MAX_LABEL_LENGTH;
  api.UNAVAILABLE_STATUS = UNAVAILABLE_STATUS;
  api.UNAVAILABLE_MESSAGE = UNAVAILABLE_MESSAGE;
  api.ERROR_UNAVAILABLE = ERROR_UNAVAILABLE;
  api.ERROR_BAD_ADAPTER = ERROR_BAD_ADAPTER;
  api.MAX_FILE_BYTES = MAX_FILE_BYTES;
  api.createTransport = createTransport;
  api.createUnavailableTransport = createUnavailableTransport;
  api.registerBrowserTransport = registerBrowserTransport;
  api.normalizeOutboundMessage = normalizeOutboundMessage;
  api.normalizeMessageQuery = normalizeMessageQuery;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  global.SimplexWebTransport = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
