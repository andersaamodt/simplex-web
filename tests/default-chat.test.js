const test = require('node:test');
const assert = require('node:assert/strict');

const ui = require('../src/default-chat.js');

test('logged out panel only shows login action', () => {
  const html = ui.renderPanel({ loggedIn: false });
  assert.match(html, /Login\.\.\./);
  assert.doesNotMatch(html, /secure-chat-input/);
});

test('signed in panel renders messages and compose area', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    messages: [
      { direction: 'incoming', text: 'hello', delivery_status: 'received', created_at: '2026-05-01T00:00:00Z' }
    ],
    draftText: 'test'
  });
  assert.match(html, /hello/);
  assert.match(html, /secure-chat-input/);
  assert.match(html, /Attach files/);
});

test('status labels map known delivery states', () => {
  assert.equal(ui.statusLabel({ delivery_status: 'sndRcvd' }), 'Delivered');
  assert.equal(ui.statusLabel({ delivery_status: 'sndSent' }), 'Sent');
  assert.equal(ui.statusLabel({ delivery_status: 'sndError' }), 'Failed');
  assert.equal(ui.statusLabel({ delivery_status: 'uploading' }), 'Uploading');
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

test('render escapes hostile admin npub attributes', () => {
  const html = ui.renderPanel({
    loggedIn: true,
    hasSigner: true,
    admin: true,
    adminMappings: [
      { npub: '" onclick="alert(1)', simplex_contact_id: 'cid', status: 'active' }
    ]
  });

  assert.doesNotMatch(html, /onclick="alert\(1\)/);
  assert.match(html, /&quot; onclick=&quot;alert\(1\)/);
});
