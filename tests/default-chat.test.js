const test = require('node:test');
const assert = require('node:assert/strict');

const ui = require('../src/default-chat.js');

function makeRoot() {
  const listeners = new Map();
  return {
    innerHTML: '',
    fields: new Map(),
    addEventListener(name, handler) {
      listeners.set(name, handler);
    },
    removeEventListener(name, handler) {
      if (listeners.get(name) === handler) {
        listeners.delete(name);
      }
    },
    querySelector(selector) {
      return this.fields.get(selector) || null;
    },
    dispatch(name, event) {
      const handler = listeners.get(name);
      if (handler) {
        handler(event);
      }
    }
  };
}

test('logged out panel only shows login action', () => {
  const html = ui.renderPanel({ loggedIn: false });
  assert.match(html, /Login\.\.\./);
  assert.doesNotMatch(html, /secure-chat-input/);
});

test('auth-pending panel shows loading instead of login action', () => {
  const html = ui.renderPanel({ loggedIn: false, loading: true });
  assert.match(html, /Loading\.\.\./);
  assert.match(html, /secure-chat-loading-spinner/);
  assert.doesNotMatch(html, /data-secure-chat-action="login"/);
  assert.doesNotMatch(html, /secure-chat-input/);
});

test('signed in panel renders messages and compose area', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    shortcutModifierLabel: '⌘',
    messages: [
      { direction: 'incoming', text: 'hello', delivery_status: 'received', created_at: '2026-05-01T00:00:00Z' }
    ],
    draftText: 'test'
  });
  assert.match(html, /hello/);
  assert.match(html, /secure-chat-input/);
  assert.match(html, /Attach files/);
  assert.match(html, /secure-chat-input-wrap/);
  assert.ok(html.indexOf('secure-chat-input-wrap') < html.indexOf('data-secure-chat-action="send"'));
  assert.match(html, /secure-chat-send-icon/);
  assert.doesNotMatch(html, />Send</);
  assert.match(html, /⌘ \+ Enter to send/);
  assert.doesNotMatch(html, /Cmd\/Ctrl\+Enter/);
});

test('signed in panel supports Ctrl shortcut label override', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    shortcutModifierLabel: 'Ctrl'
  });
  assert.match(html, /Ctrl \+ Enter to send/);
});

test('signed in panel renders image video and arbitrary attachments in place', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    messages: [
      {
        direction: 'incoming',
        text: 'image',
        delivery_status: 'received',
        attachment: { name: 'pixel.png', mime: 'image/png', size: 67, data_url: 'data:image/png;base64,aGVsbG8=' }
      },
      {
        direction: 'incoming',
        text: 'video',
        delivery_status: 'received',
        attachment: { name: 'clip.mp4', mime: 'video/mp4', size: 12, data_url: 'data:video/mp4;base64,aGVsbG8=' }
      },
      {
        direction: 'incoming',
        text: 'document',
        delivery_status: 'received',
        attachment: { name: 'notes.bin', mime: 'application/octet-stream', size: 5, data_url: 'data:application/octet-stream;base64,aGVsbG8=' }
      }
    ]
  });
  assert.match(html, /<img class="secure-chat-attachment-media" src="data:image\/png;base64,aGVsbG8="/);
  assert.match(html, /<video class="secure-chat-attachment-media" src="data:video\/mp4;base64,aGVsbG8=" controls/);
  assert.match(html, /download="notes\.bin"/);
  assert.match(html, /application\/octet-stream · 5 B/);
});

test('status labels map known delivery states', () => {
  assert.equal(ui.statusLabel({ delivery_status: 'sndRcvd' }), 'Delivered');
  assert.equal(ui.statusLabel({ delivery_status: 'sndSent' }), 'Sent');
  assert.equal(ui.statusLabel({ delivery_status: 'sndNew' }), 'Sending...');
  assert.equal(ui.statusLabel({ delivery_status: 'sndError' }), 'Failed');
  assert.equal(ui.statusLabel({ delivery_status: 'uploading' }), 'Uploading');
  assert.match(ui.statusHtml({ delivery_status: 'sending' }), /secure-chat-status-spinner/);
  assert.doesNotMatch(ui.statusHtml({ delivery_status: 'sent' }), /secure-chat-status-spinner/);
});

test('rendered spinners inherit the current animation phase', () => {
  assert.match(ui.spinnerPhaseStyle(), /^ style="animation-delay:-\d+ms"$/);
  assert.match(ui.statusHtml({ delivery_status: 'sending' }), /secure-chat-status-spinner" style="animation-delay:-\d+ms" aria-hidden="true"/);

  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    sending: true,
    messages: [
      { direction: 'outgoing', text: 'phase test', delivery_status: 'sending', created_at: '2026-05-01T00:00:00Z' }
    ]
  });

  assert.match(html, /secure-chat-status-spinner" style="animation-delay:-\d+ms" aria-hidden="true"/);
  assert.match(html, /secure-chat-send-spinner" style="animation-delay:-\d+ms" aria-hidden="true"/);
});

test('render escapes hostile message HTML', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    messages: [
      { direction: 'incoming', text: '<script>alert(1)</script>', delivery_status: 'received', created_at: '2026-05-01T00:00:00Z' }
    ]
  });
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test('render escapes hostile attachment metadata', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    messages: [
      {
        direction: 'incoming',
        delivery_status: 'received',
        attachment: {
          name: 'bad"><script>alert(1)</script>.png',
          mime: 'image/png',
          size: 10,
          data_url: 'data:image/png;base64,aGVsbG8='
        }
      }
    ]
  });
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /bad&quot;&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test('render clamps hostile upload progress and ignores oversized history', () => {
  const messages = Array.from({ length: ui.MAX_RENDER_MESSAGES + 10 }, (_, index) => ({
    direction: index === ui.MAX_RENDER_MESSAGES + 9 ? 'incoming' : 'outgoing',
    text: `message-${index + 1}`,
    delivery_status: 'received',
    created_at: '2026-05-01T00:00:00Z'
  }));
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    messages,
    uploads: [
      { name: 'bad.txt', status: 'uploading', progress: '100;background:red' },
      { name: 'nan.txt', status: 'uploading', progress: Infinity },
      { name: 'huge.txt', status: 'uploading', progress: 9999 }
    ]
  });

  assert.doesNotMatch(html, />message-1</);
  assert.match(html, />message-210</);
  assert.equal((html.match(/width:0%/g) || []).length >= 2, true);
  assert.match(html, /width:100%/);
  assert.doesNotMatch(html, /background:red/);
});

test('does not render admin mapping console inline', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    admin: true,
    adminMappings: [
      { npub: '" onclick="alert(1)', simplex_contact_id: 'cid', status: 'active' }
    ]
  });

  assert.doesNotMatch(html, /Admin Mapping Console/);
  assert.doesNotMatch(html, /data-secure-chat-action="admin-refresh"/);
  assert.doesNotMatch(html, /data-secure-chat-action="deactivate"/);
  assert.doesNotMatch(html, /data-secure-chat-action="delete"/);
  assert.doesNotMatch(html, /onclick="alert\(1\)/);
});

test('render escapes textarea and service banner hostile input', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    draftText: '</textarea><script>alert(1)</script>',
    service: {
      transport_status: 'broken"><img src=x onerror=alert(1)>',
      transport_error: '</div><script>alert(2)</script>'
    }
  });

  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.doesNotMatch(html, /<img src=x onerror=alert\(1\)>/);
  assert.match(html, /&lt;\/textarea&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /&lt;\/div&gt;&lt;script&gt;alert\(2\)&lt;\/script&gt;/);
});

test('mount truncates hostile draft values and admin keys before callbacks', () => {
  const root = makeRoot();
  const calls = [];
  root.fields.set('#secure-chat-input', { value: 'x'.repeat(5000) });
  ui.mount(root, { loggedIn: true, hasSigner: true, admin: true }, {
    onSend(value) {
      calls.push(['send', value.length]);
    },
    onDraftChange(value) {
      calls.push(['draft', value.length]);
    },
    onAdminDelete(value) {
      calls.push(['delete', value.length]);
    }
  });

  root.dispatch('input', { target: { id: 'secure-chat-input', value: 'y'.repeat(5000) } });
  root.dispatch('click', {
    target: {
      closest() {
        return {
          getAttribute(name) {
            if (name === 'data-secure-chat-action') return 'send';
            return '';
          }
        };
      }
    }
  });
  root.dispatch('click', {
    target: {
      closest() {
        return {
          getAttribute(name) {
            if (name === 'data-secure-chat-action') return 'delete';
            if (name === 'data-secure-chat-npub') return 'n'.repeat(500);
            return '';
          }
        };
      }
    }
  });

  assert.deepEqual(calls, [
    ['draft', ui.MAX_TEXT_LENGTH],
    ['send', ui.MAX_TEXT_LENGTH],
    ['delete', ui.MAX_LABEL_LENGTH]
  ]);
});

test('mount destroy removes event handlers', () => {
  const root = makeRoot();
  let sendCount = 0;
  const mounted = ui.mount(root, { loggedIn: true, hasSigner: true }, {
    onSend() {
      sendCount += 1;
    }
  });
  root.fields.set('#secure-chat-input', { value: 'hello' });
  mounted.destroy();
  root.dispatch('click', {
    target: {
      closest() {
        return {
          getAttribute(name) {
            return name === 'data-secure-chat-action' ? 'send' : '';
          }
        };
      }
    }
  });
  assert.equal(sendCount, 0);
});
