(function (global) {
  'use strict';

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

  function statusLabel(message) {
    var raw = String(message && message.delivery_status || '').trim();
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
    return {
      loggedIn: !!next.loggedIn,
      hasSigner: next.hasSigner !== false,
      error: String(next.error || ''),
      sending: !!next.sending,
      draftText: String(next.draftText || ''),
      service: next.service && typeof next.service === 'object' ? next.service : null,
      messages: Array.isArray(next.messages) ? next.messages : [],
      uploads: Array.isArray(next.uploads) ? next.uploads : [],
      admin: !!next.admin,
      adminMappings: Array.isArray(next.adminMappings) ? next.adminMappings : []
    };
  }

  function renderPanel(model) {
    var state = normalizeModel(model);
    var html = '<section class="secure-chat-panel" aria-labelledby="secure-chat-title">';
    html += '<div class="secure-chat-head">';
    html += '<div class="secure-chat-heading"><h2 id="secure-chat-title">Secure Chat</h2></div>';
    if (!state.loggedIn) {
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
        var progress = Number(upload && upload.progress || 0);
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
    html += '<label class="secure-chat-attach-button"><input id="secure-chat-file-input" type="file" multiple hidden>Attach files</label>';
    html += '<button type="button" class="list-admin-primary-btn" data-secure-chat-action="send"' + (state.sending ? ' disabled' : '') + '>' + (state.sending ? 'Sending...' : 'Send') + '</button>';
    html += '<span class="secure-chat-compose-hint">Cmd/Ctrl+Enter to send</span>';
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
        return String(field.value || '');
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
      var npub = String(actionNode.getAttribute('data-secure-chat-npub') || '');
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
      state.draftText = String(target.value || '');
      if (typeof actions.onDraftChange === 'function') {
        actions.onDraftChange(state.draftText);
      }
    }

    function onChange(event) {
      var target = event.target;
      if (!target || target.id !== 'secure-chat-file-input' || !target.files) return;
      if (typeof actions.onFilesSelected === 'function') {
        actions.onFilesSelected(Array.prototype.slice.call(target.files));
      }
      target.value = '';
    }

    function onKeyDown(event) {
      var target = event.target;
      if (!target || target.id !== 'secure-chat-input') return;
      if (event.key === 'Enter' && (event.metaKey || event.ctrlKey) && typeof actions.onSend === 'function') {
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
    escapeHtml: escapeHtml,
    escapeAttr: escapeAttr,
    statusLabel: statusLabel,
    renderPanel: renderPanel,
    mount: mount
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  global.SimplexWebDefaultChat = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);

