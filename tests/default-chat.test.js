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

