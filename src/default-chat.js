(function (global) {
  'use strict';

  var MAX_RENDER_MESSAGES = 200;
  var MAX_RENDER_UPLOADS = 50;
  var MAX_TEXT_LENGTH = 4000;
  var MAX_LABEL_LENGTH = 256;
  var MAX_STATUS_LENGTH = 64;

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function escapeAttr(value) {
    return escapeHtml(value);
  }

  function limitString(value, maxLength) {
    return String(value == null ? '' : value).slice(0, maxLength);
  }

  function clampProgress(value) {
    var progress = Number(value);
    if (!isFinite(progress)) {
      return 0;
    }
    progress = Math.floor(progress);
    if (progress < 0) return 0;
    if (progress > 100) return 100;
    return progress;
  }

  function clampNonNegativeInteger(value) {
    var count = Number(value);
    if (!isFinite(count) || count < 0) {
      return 0;
    }
    return Math.floor(count);
  }

  function normalizeAttachment(value) {
    var next = value && typeof value === 'object' ? value : null;
    if (!next) {
      return null;
    }
    return {
      name: limitString(next.name || 'Attachment', MAX_LABEL_LENGTH),
      mime: limitString(next.mime || '', MAX_LABEL_LENGTH),
      size: clampNonNegativeInteger(next.size),
      upload_id: limitString(next.upload_id || '', MAX_LABEL_LENGTH)
    };
  }

  function normalizeMessage(value) {
    var next = value && typeof value === 'object' ? value : {};
    var direction = String(next.direction || '').trim().toLowerCase() === 'incoming' ? 'incoming' : 'outgoing';
    return {
      direction: direction,
      message_kind: String(next.message_kind || '').trim().toLowerCase() === 'file' ? 'file' : 'text',
      delivery_status: limitString(next.delivery_status || '', MAX_STATUS_LENGTH),
      created_at: limitString(next.created_at || '', MAX_LABEL_LENGTH),
      text: limitString(next.text || '', MAX_TEXT_LENGTH),
      attachment: normalizeAttachment(next.attachment)
    };
  }

  function normalizeUpload(value) {
    var next = value && typeof value === 'object' ? value : {};
    return {
      upload_id: limitString(next.upload_id || '', MAX_LABEL_LENGTH),
      name: limitString(next.name || 'Attachment', MAX_LABEL_LENGTH),
      status: limitString(next.status || 'queued', MAX_STATUS_LENGTH),
      progress: clampProgress(next.progress)
    };
  }

  function normalizeAdminRow(value) {
    var next = value && typeof value === 'object' ? value : {};
    return {
      npub: limitString(next.npub || '', MAX_LABEL_LENGTH),
      simplex_contact_id: limitString(next.simplex_contact_id || '', MAX_LABEL_LENGTH),
      status: limitString(next.status || '', MAX_STATUS_LENGTH)
    };
  }

  function normalizeService(value) {
    var next = value && typeof value === 'object' ? value : null;
    if (!next) {
      return null;
    }
    return {
      transport_status: limitString(next.transport_status || '', MAX_STATUS_LENGTH),
      transport_error: limitString(next.transport_error || '', MAX_TEXT_LENGTH)
    };
  }

  function statusLabel(message) {
    var raw = limitString(message && message.delivery_status || '', MAX_STATUS_LENGTH).trim();
    switch (raw) {
      case 'sndRcvd':
      case 'delivered':
        return 'Delivered';
      case 'sndSent':
      case 'sent':
        return 'Sent';
      case 'failed':
      case 'sndError':
      case 'sndErrorAuth':
        return 'Failed';
      case 'warning':
      case 'sndWarning':
        return 'Warning';
      case 'received':
      case 'rcvNew':
      case 'rcvRead':
        return 'Received';
      case 'sndNew':
      case 'sending':
        return 'Sending';
      case 'uploading':
        return 'Uploading';
      default:
        return raw ? raw : 'Queued';
    }
  }

  function normalizeModel(model) {
    var next = model && typeof model === 'object' ? model : {};
    var messages = Array.isArray(next.messages) ? next.messages.slice(-MAX_RENDER_MESSAGES).map(normalizeMessage) : [];
    var uploads = Array.isArray(next.uploads) ? next.uploads.slice(-MAX_RENDER_UPLOADS).map(normalizeUpload) : [];
    var adminMappings = Array.isArray(next.adminMappings) ? next.adminMappings.slice(0, MAX_RENDER_MESSAGES).map(normalizeAdminRow) : [];
    return {
      loggedIn: !!next.loggedIn,
      loading: !!next.loading,
      hasSigner: next.hasSigner !== false,
      error: limitString(next.error || '', MAX_TEXT_LENGTH),
      sending: !!next.sending,
      draftText: limitString(next.draftText || '', MAX_TEXT_LENGTH),
      service: normalizeService(next.service),
      messages: messages,
      uploads: uploads,
      sendWithModifier: next.sendWithModifier === true,
      simplexWebIntroDismissed: next.simplexWebIntroDismissed === true,
      admin: !!next.admin,
      adminMappings: adminMappings
    };
  }

  function renderSimplexWebIntro() {
    var html = '<aside class="secure-chat-simplex-info" role="note">';
    html += '<button type="button" class="secure-chat-simplex-dismiss" data-secure-chat-action="dismiss-simplex-info" aria-label="Dismiss Secure Chat info" title="Dismiss">';
    html += '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    html += '</button>';
    html += '<p>Messages are sent over SimpleX Chat using <a href="https://github.com/andersaamodt/simplex-web" rel="noopener noreferrer">simplex-web</a>, so encryption and delivery happen in the browser instead of exposing plaintext to this server. SimpleX uses end-to-end encrypted pairwise queues, so relays do not need public user identities to pass messages.</p>';
    html += '</aside>';
    return html;
  }

  function renderPanel(model) {
    var state = normalizeModel(model);
    var html = '<section class="secure-chat-panel" aria-labelledby="secure-chat-title">';
    html += '<div class="secure-chat-head">';
    html += '<div class="secure-chat-heading"><h2 id="secure-chat-title">Secure Chat</h2></div>';
    if (!state.loggedIn && state.loading) {
      html += '<div class="secure-chat-loading" role="status" aria-live="polite"><span>Loading...</span><span class="save-spinner secure-chat-loading-spinner" aria-hidden="true"></span></div>';
    } else if (!state.loggedIn) {
      html += '<button type="button" class="list-admin-primary-btn secure-chat-login-btn" data-secure-chat-action="login">Login...</button>';
    }
    html += '</div>';
    if (!state.loggedIn) {
      html += '</section>';
      return html;
    }
    if (!state.hasSigner) {
      html += '<p class="secure-chat-empty">Secure Chat requires a browser signer extension so each request can be signed.</p>';
      html += '</section>';
      return html;
    }
    if (state.error) {
      html += '<div class="secure-chat-banner is-error">' + escapeHtml(state.error) + '</div>';
    }
    if (state.service && state.service.transport_status && state.service.transport_status !== 'connected') {
      html += '<div class="secure-chat-banner is-warn">Transport status: ' + escapeHtml(String(state.service.transport_status || 'unknown'));
      if (state.service.transport_error) {
        html += ' · ' + escapeHtml(String(state.service.transport_error || ''));
      }
      html += '</div>';
    }
    html += '<div class="secure-chat-thread" id="secure-chat-thread">';
    if (!state.simplexWebIntroDismissed) {
      html += renderSimplexWebIntro();
    }
    if (state.messages.length) {
      state.messages.forEach(function (message) {
        var incoming = String(message && message.direction || '') === 'incoming';
        html += '<article class="secure-chat-message' + (incoming ? ' is-incoming' : ' is-outgoing') + '">';
        html += '<div class="secure-chat-bubble">';
        if (message && message.text) {
          html += '<p class="secure-chat-text">' + escapeHtml(String(message.text || '')).replace(/\n/g, '<br>') + '</p>';
        }
        if (message && message.attachment) {
          html += '<p class="secure-chat-attachment">' + escapeHtml(String(message.attachment.name || 'Attachment')) + ' <span>' + escapeHtml(statusLabel(message)) + '</span></p>';
        }
        html += '<div class="secure-chat-meta"><span>' + escapeHtml(statusLabel(message)) + '</span><time>' + escapeHtml(String(message && message.created_at || '')) + '</time></div>';
        html += '</div>';
        html += '</article>';
      });
    } else {
      html += '<p class="secure-chat-empty">No secure chat messages yet.</p>';
    }
    html += '</div>';
    if (state.uploads.length) {
      html += '<div class="secure-chat-uploads">';
      state.uploads.forEach(function (upload) {
        var progress = clampProgress(upload && upload.progress);
        html += '<div class="secure-chat-upload-row">';
        html += '<div class="secure-chat-upload-name">' + escapeHtml(String(upload && upload.name || 'Attachment')) + '</div>';
        html += '<div class="secure-chat-upload-meta"><span>' + escapeHtml(String(upload && upload.status || 'queued')) + '</span><span>' + String(progress) + '%</span></div>';
        html += '<div class="secure-chat-upload-bar"><span style="width:' + String(progress) + '%"></span></div>';
        html += '</div>';
      });
      html += '</div>';
    }
    html += '<div class="secure-chat-compose">';
    html += '<textarea id="secure-chat-input" class="secure-chat-input" rows="4" placeholder="Write a secure message">' + escapeHtml(state.draftText) + '</textarea>';
    html += '<div class="secure-chat-actions">';
    html += '<label class="secure-chat-attach-button" aria-label="Attach files" title="Attach files"><input id="secure-chat-file-input" type="file" multiple hidden><svg class="secure-chat-attach-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M21.44 11.05 12.25 20.24a6 6 0 0 1-8.49-8.49l9.9-9.9a4 4 0 0 1 5.66 5.66l-9.9 9.9a2 2 0 1 1-2.83-2.83l8.49-8.49"/></svg></label>';
    html += '<button type="button" class="list-admin-primary-btn secure-chat-send-btn" data-secure-chat-action="send"' + (state.sending ? ' disabled aria-busy="true"' : '') + '>' + (state.sending ? '<span class="save-spinner secure-chat-send-spinner" aria-hidden="true"></span><span>Sending...</span>' : 'Send') + '</button>';
    html += '<label class="secure-chat-compose-hint secure-chat-send-shortcut"><input id="secure-chat-send-modifier" type="checkbox"' + (state.sendWithModifier === true ? ' checked' : '') + '> Cmd/Ctrl+Enter to send</label>';
    html += '</div>';
    html += '</div>';
    if (state.admin) {
      html += '<details class="secure-chat-admin-panel">';
      html += '<summary>Admin Mapping Console</summary>';
      html += '<div class="secure-chat-admin-actions"><button type="button" data-secure-chat-action="admin-refresh">Refresh</button></div>';
      html += '<div class="secure-chat-admin-table">';
      state.adminMappings.forEach(function (row) {
        html += '<div class="secure-chat-admin-row">';
        html += '<span class="secure-chat-admin-npub">' + escapeHtml(String(row && row.npub || '')) + '</span>';
        html += '<span class="secure-chat-admin-contact">' + escapeHtml(String(row && row.simplex_contact_id || '')) + '</span>';
        html += '<span class="secure-chat-admin-status">' + escapeHtml(String(row && row.status || '')) + '</span>';
        html += '<button type="button" data-secure-chat-action="deactivate" data-secure-chat-npub="' + escapeAttr(String(row && row.npub || '')) + '">Deactivate</button>';
        html += '<button type="button" data-secure-chat-action="delete" data-secure-chat-npub="' + escapeAttr(String(row && row.npub || '')) + '">Delete Mapping</button>';
        html += '</div>';
      });
      if (!state.adminMappings.length) {
        html += '<p class="secure-chat-empty">No mappings yet.</p>';
      }
      html += '</div>';
      html += '</details>';
    }
    html += '</section>';
    return html;
  }

  function mount(root, model, handlers) {
    if (!root || typeof root.innerHTML === 'undefined') {
      throw new Error('A root element is required');
    }
    var state = normalizeModel(model);
    var api = {};
    var actions = handlers && typeof handlers === 'object' ? handlers : {};

    function render(nextModel) {
      if (nextModel && typeof nextModel === 'object') {
        state = normalizeModel(nextModel);
      }
      root.innerHTML = renderPanel(state);
      return state;
    }

    function currentDraftValue() {
      var field = root.querySelector('#secure-chat-input');
      if (field && typeof field.value === 'string') {
        return limitString(field.value || '', MAX_TEXT_LENGTH);
      }
      return state.draftText;
    }

    function onClick(event) {
      var target = event.target;
      if (!target || typeof target.closest !== 'function') return;
      var actionNode = target.closest('[data-secure-chat-action]');
      if (!actionNode) return;
      var action = String(actionNode.getAttribute('data-secure-chat-action') || '').trim().toLowerCase();
      if (!action) return;
      if (action === 'login' && typeof actions.onLogin === 'function') {
        actions.onLogin();
        return;
      }
      if (action === 'send' && typeof actions.onSend === 'function') {
        actions.onSend(currentDraftValue());
        return;
      }
      if (action === 'admin-refresh' && typeof actions.onAdminRefresh === 'function') {
        actions.onAdminRefresh();
        return;
      }
      var npub = limitString(actionNode.getAttribute('data-secure-chat-npub') || '', MAX_LABEL_LENGTH);
      if (action === 'deactivate' && typeof actions.onAdminDeactivate === 'function') {
        actions.onAdminDeactivate(npub);
        return;
      }
      if (action === 'delete' && typeof actions.onAdminDelete === 'function') {
        actions.onAdminDelete(npub);
      }
    }

    function onInput(event) {
      var target = event.target;
      if (!target || target.id !== 'secure-chat-input') return;
      state.draftText = limitString(target.value || '', MAX_TEXT_LENGTH);
      if (typeof actions.onDraftChange === 'function') {
        actions.onDraftChange(state.draftText);
      }
    }

    function onChange(event) {
      var target = event.target;
      if (!target) return;
      if (target.id === 'secure-chat-send-modifier') {
        state.sendWithModifier = target.checked === true;
        if (typeof actions.onSendShortcutChange === 'function') {
          actions.onSendShortcutChange(state.sendWithModifier);
        }
        return;
      }
      if (target.id !== 'secure-chat-file-input' || !target.files) return;
      if (typeof actions.onFilesSelected === 'function') {
        actions.onFilesSelected(Array.prototype.slice.call(target.files));
      }
      target.value = '';
    }

    function onKeyDown(event) {
      var target = event.target;
      if (!target || target.id !== 'secure-chat-input') return;
      if (event.key === 'Enter' && typeof actions.onSend === 'function') {
        if (event.shiftKey) {
          return;
        }
        if (state.sendWithModifier === true && !(event.metaKey || event.ctrlKey)) {
          return;
        }
        event.preventDefault();
        actions.onSend(currentDraftValue());
      }
    }

    root.addEventListener('click', onClick);
    root.addEventListener('input', onInput);
    root.addEventListener('change', onChange);
    root.addEventListener('keydown', onKeyDown);

    api.render = render;
    api.getState = function () {
      return normalizeModel(state);
    };
    api.destroy = function () {
      root.removeEventListener('click', onClick);
      root.removeEventListener('input', onInput);
      root.removeEventListener('change', onChange);
      root.removeEventListener('keydown', onKeyDown);
    };

    render(state);
    return api;
  }

  var api = {
    MAX_RENDER_MESSAGES: MAX_RENDER_MESSAGES,
    MAX_RENDER_UPLOADS: MAX_RENDER_UPLOADS,
    MAX_TEXT_LENGTH: MAX_TEXT_LENGTH,
    MAX_LABEL_LENGTH: MAX_LABEL_LENGTH,
    MAX_STATUS_LENGTH: MAX_STATUS_LENGTH,
    escapeHtml: escapeHtml,
    escapeAttr: escapeAttr,
    clampProgress: clampProgress,
    normalizeModel: normalizeModel,
    statusLabel: statusLabel,
    renderPanel: renderPanel,
    mount: mount
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  global.SimplexWebDefaultChat = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
