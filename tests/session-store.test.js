const test = require('node:test');
const assert = require('node:assert/strict');

const store = require('../src/session-store.js');

function makeStorage() {
  const values = new Map();
  return {
    getItem(key) {
      return values.has(key) ? values.get(key) : null;
    },
    setItem(key, value) {
      values.set(key, String(value));
    },
    removeItem(key) {
      values.delete(key);
    }
  };
}

test('session store writes and reads bounded chat state', () => {
  const storage = makeStorage();
  const messages = [];
  for (let i = 1; i <= 60; i += 1) {
    messages.push({
      seq: i,
      direction: i % 2 === 0 ? 'incoming' : 'outgoing',
      text: `message-${i}`,
      delivery_status: 'sent',
      created_at: `local-${String(i).padStart(4, '0')}`
    });
  }
  const uploads = [];
  for (let i = 1; i <= 25; i += 1) {
    uploads.push({ upload_id: `upl-${i}`, name: `file-${i}.txt`, status: 'complete', progress: 100 });
  }

  const written = store.writeSession(storage, 'new.andersaamodt.com/contact', 'npub1example', {
    draftText: 'draft text',
    lastSeq: 60,
    messages,
    uploads
  });
  const roundTrip = store.readSession(storage, 'new.andersaamodt.com/contact', 'npub1example');

  assert.equal(written.messages.length, store.MAX_MESSAGES);
  assert.equal(written.messages[0].seq, 11);
  assert.equal(roundTrip.messages.length, store.MAX_MESSAGES);
  assert.equal(roundTrip.messages[0].seq, 11);
  assert.equal(roundTrip.messages[roundTrip.messages.length - 1].seq, 60);
  assert.equal(roundTrip.uploads.length, store.MAX_UPLOADS);
  assert.equal(roundTrip.uploads[0].upload_id, 'upl-6');
  assert.equal(roundTrip.draftText, 'draft text');
  assert.equal(roundTrip.lastSeq, 60);
  assert.match(roundTrip.savedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('session store tolerates invalid JSON and hostile keys', () => {
  const storage = makeStorage();
  const key = store.buildStorageKey('../Local Host', 'NPUB1 Example/../../');
  storage.setItem(key, '{not valid json');

  const session = store.readSession(storage, '../Local Host', 'NPUB1 Example/../../');
  assert.equal(session.messages.length, 0);
  assert.equal(session.uploads.length, 0);
  assert.equal(session.draftText, '');
  assert.equal(key, 'simplex-web-session-v1:local-host:npub1-example');
});

test('session store truncates hostile key parts and oversized stored blobs', () => {
  const storage = makeStorage();
  const longPart = 'A'.repeat(400) + '/../' + 'B'.repeat(400);
  const key = store.buildStorageKey(longPart, longPart);
  storage.setItem(key, 'x'.repeat(store.MAX_STORED_JSON_LENGTH + 1));

  const session = store.readSession(storage, longPart, longPart);
  assert.equal(session.messages.length, 0);
  assert.equal(session.uploads.length, 0);
  assert.equal(key.length <= ('simplex-web-session-v1::'.length + store.MAX_KEY_PART_LENGTH * 2), true);
});

test('session store can clear a saved session', () => {
  const storage = makeStorage();
  store.writeSession(storage, 'site', 'account', { draftText: 'hello' });
  assert.equal(store.readSession(storage, 'site', 'account').draftText, 'hello');
  assert.equal(store.clearSession(storage, 'site', 'account'), true);
  assert.equal(store.readSession(storage, 'site', 'account').draftText, '');
});

test('session store slices before normalizing hostile oversized history', () => {
  const sentinel = {};
  Object.defineProperty(sentinel, 'text', {
    get() {
      throw new Error('head entry should not be normalized');
    }
  });

  const messages = [sentinel];
  for (let i = 1; i <= store.MAX_MESSAGES; i += 1) {
    messages.push({ seq: i, direction: 'incoming', text: `tail-${i}` });
  }

  const session = store.normalizeSession({ messages });
  assert.equal(session.messages.length, store.MAX_MESSAGES);
  assert.equal(session.messages[0].text, 'tail-1');
});

test('session store clamps hostile progress and truncates oversized strings', () => {
  const session = store.normalizeSession({
    draftText: 'x'.repeat(5000),
    messages: [
      {
        seq: 1,
        direction: 'sideways',
        message_kind: 'weird',
        delivery_status: 's'.repeat(200),
        text: 'm'.repeat(5000),
        attachment: { name: 'image.png', mime: 'image/png', size: 3, data_url: 'data:image/png;base64,aGVsbG8=' },
        error_detail: 'e'.repeat(5000)
      }
    ],
    uploads: [
      { progress: 9999, name: 'n'.repeat(400), status: 'u'.repeat(200), error: 'f'.repeat(5000) }
    ]
  });

  assert.equal(session.draftText.length, 4000);
  assert.equal(session.messages[0].direction, 'outgoing');
  assert.equal(session.messages[0].message_kind, 'text');
  assert.equal(session.messages[0].delivery_status.length, 64);
  assert.equal(session.messages[0].text.length, 4000);
  assert.equal(session.messages[0].attachment.data_url, 'data:image/png;base64,aGVsbG8=');
  assert.equal(session.messages[0].error_detail.length, 4000);
  assert.equal(session.uploads[0].progress, 100);
  assert.equal(session.uploads[0].name.length, 256);
  assert.equal(session.uploads[0].status.length, 64);
  assert.equal(session.uploads[0].error.length, 4000);
});

test('session store tolerates storage write and remove failures', () => {
  const storage = {
    getItem() {
      return null;
    },
    setItem() {
      throw new Error('quota exceeded');
    },
    removeItem() {
      throw new Error('blocked');
    }
  };

  const written = store.writeSession(storage, 'site', 'account', {
    draftText: 'hello',
    uploads: [{ progress: -50 }]
  });
  assert.equal(written.draftText, 'hello');
  assert.equal(written.uploads[0].progress, 0);
  assert.equal(store.clearSession(storage, 'site', 'account'), false);
});
