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
  assert.match(html, /class="secure-chat-file-input"/);
  assert.doesNotMatch(html, /secure-chat-file-input" type="file" multiple hidden/);
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

test('signed in panel renders pending attachment pills above the draft', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    draftText: 'caption',
    pendingFiles: [
      { id: 'file-1', name: 'photo.png', mime: 'image/png', size: 2048 }
    ]
  });

  assert.match(html, /secure-chat-input-wrap has-pending-files/);
  assert.match(html, /secure-chat-pending-files/);
  assert.ok(html.indexOf('secure-chat-pending-files') < html.indexOf('id="secure-chat-input"'));
  assert.match(html, /photo\.png/);
  assert.match(html, /2 KB/);
  assert.match(html, /data-secure-chat-action="remove-pending-file"/);
  assert.match(html, /data-secure-chat-file-id="file-1"/);
});

test('signed in panel renders image video audio and arbitrary attachments in place', () => {
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
      },
      {
        direction: 'incoming',
        text: 'audio',
        delivery_status: 'received',
        attachment: { name: 'voice.mp3', mime: 'audio/mpeg', size: 42, data_url: 'data:audio/mpeg;base64,aGVsbG8=' }
      }
    ]
  });
  assert.match(html, /<img class="secure-chat-attachment-media" src="data:image\/png;base64,aGVsbG8="/);
  assert.match(html, /<video class="secure-chat-attachment-media" src="data:video\/mp4;base64,aGVsbG8=" controls/);
  assert.match(html, /<audio class="secure-chat-attachment-audio" src="data:audio\/mpeg;base64,aGVsbG8=" controls/);
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

test('render drops unsafe attachment URLs before placing them in HTML attributes', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    messages: [
      {
        direction: 'incoming',
        delivery_status: 'received',
        attachment: {
          name: 'unsafe.png',
          mime: 'image/png',
          size: 10,
          data_url: 'javascript:alert(1)'
        }
      },
      {
        direction: 'incoming',
        delivery_status: 'received',
        attachment: {
          name: 'html.png',
          mime: 'image/png',
          size: 11,
          data_url: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
        }
      }
    ]
  });

  assert.doesNotMatch(html, /javascript:alert/);
  assert.doesNotMatch(html, /data:text\/html/);
  assert.doesNotMatch(html, /<img class="secure-chat-attachment-media"/);
  assert.equal((html.match(/href="#"/g) || []).length, 2);
});

test('render refuses remote relative and loopback attachment URL autoloads', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    messages: [
      {
        direction: 'incoming',
        delivery_status: 'received',
        attachment: { name: 'remote.png', mime: 'image/png', size: 1, url: 'https://evil.example/pixel.png' }
      },
      {
        direction: 'incoming',
        delivery_status: 'received',
        attachment: { name: 'relative.png', mime: 'image/png', size: 1, url: '/files?path=/tmp/secret.png' }
      },
      {
        direction: 'incoming',
        delivery_status: 'received',
        attachment: { name: 'local.png', mime: 'image/png', size: 1, url: 'http://127.0.0.1:5226/files?path=%2Ftmp%2Fok.png' }
      }
    ]
  });

  assert.doesNotMatch(html, /evil\.example/);
  assert.doesNotMatch(html, /\/files\?path=\/tmp\/secret\.png/);
  assert.doesNotMatch(html, /127\.0\.0\.1:5226/);
  assert.equal((html.match(/<img class="secure-chat-attachment-media"/g) || []).length, 0);
  assert.equal((html.match(/href="#"/g) || []).length, 3);
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

test('mount ignores delegated actions resolved outside the mounted root', () => {
  const listeners = new Map();
  const outsideActionNode = {
    getAttribute(name) {
      return name === 'data-secure-chat-action' ? 'send' : '';
    }
  };
  const insideActionNode = {
    inside: true,
    getAttribute(name) {
      return name === 'data-secure-chat-action' ? 'send' : '';
    }
  };
  const root = {
    innerHTML: '',
    addEventListener(name, handler) {
      listeners.set(name, handler);
    },
    removeEventListener() {},
    querySelector(selector) {
      return selector === '#secure-chat-input' ? { value: 'root draft' } : null;
    },
    contains(node) {
      return !!(node && node.inside === true);
    },
    dispatch(name, event) {
      listeners.get(name)(event);
    }
  };
  const calls = [];

  ui.mount(root, { loggedIn: true, hasSigner: true }, {
    onSend(value) {
      calls.push(value);
    }
  });

  root.dispatch('click', {
    target: {
      closest() {
        return outsideActionNode;
      }
    }
  });
  root.dispatch('click', {
    target: {
      closest() {
        return insideActionNode;
      }
    }
  });

  assert.deepEqual(calls, ['root draft']);
});

test('mount dispatches pending file removal and dropped files', () => {
  const root = makeRoot();
  const calls = [];
  ui.mount(root, { loggedIn: true, hasSigner: true }, {
    onRemovePendingFile(id) {
      calls.push(['remove', id]);
    },
    onFilesSelected(files) {
      calls.push(['files', files.map((file) => file.name)]);
    }
  });

  root.dispatch('click', {
    target: {
      closest() {
        return {
          getAttribute(name) {
            if (name === 'data-secure-chat-action') return 'remove-pending-file';
            if (name === 'data-secure-chat-file-id') return 'file-1';
            return '';
          }
        };
      }
    }
  });
  const dropped = [{ name: 'drop.txt' }];
  root.dispatch('drop', {
    preventDefault() {
      calls.push(['prevented']);
    },
    dataTransfer: { files: dropped }
  });

  assert.deepEqual(calls, [
    ['remove', 'file-1'],
    ['prevented'],
    ['files', ['drop.txt']]
  ]);
});

test('mount preserves simplex-web info banner node across refresh renders', () => {
  const calls = [];
  const stableInfo = { id: 'stable-info' };
  const nextInfo = {
    replaceWith(node) {
      calls.push(node);
    }
  };
  let queryCount = 0;
  const root = {
    innerHTML: '',
    addEventListener() {},
    removeEventListener() {},
    querySelector(selector) {
      if (selector !== '.secure-chat-thread > .secure-chat-simplex-info') {
        return null;
      }
      queryCount += 1;
      return queryCount === 1 ? stableInfo : nextInfo;
    }
  };

  const mounted = ui.mount(root, { loggedIn: true, hasSigner: true }, {});
  mounted.render({ loggedIn: true, hasSigner: true, messages: [{ text: 'fresh' }] });

  assert.deepEqual(calls, [stableInfo]);
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
