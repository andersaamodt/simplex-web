import test from 'node:test';
import assert from 'node:assert/strict';

import { createBrowserSimplexStore, SIMPLEX_STORE_MAX_LIST_ITEMS } from '../src/browser-simplex-store.mjs';

function storage() {
  const map = new Map();
  return {
    getItem(key) { return map.has(key) ? map.get(key) : null; },
    setItem(key, value) { map.set(String(key), String(value)); },
    removeItem(key) { map.delete(String(key)); },
    key(index) { return Array.from(map.keys())[index] || null; },
    get length() { return map.size; }
  };
}

test('durable store round-trips binary queue contact and ratchet records', () => {
  const store = createBrowserSimplexStore({ storage: storage(), namespace: 'test' });
  store.saveQueue('alice:inbox', { rcvId: new Uint8Array([1, 2, 3]) });
  store.saveContact('alice', { state: 'active', queue: 'alice:inbox' });
  store.saveRatchet('alice', { rootKey: new Uint8Array(32).fill(7) });

  assert.deepEqual(Array.from(store.loadQueue('alice:inbox').rcvId), [1, 2, 3]);
  assert.equal(store.loadContact('alice').state, 'active');
  assert.equal(store.loadRatchet('alice').rootKey.length, 32);
  assert.equal(store.listQueues().length, 1);

  store.deleteRatchet('alice');
  assert.equal(store.loadRatchet('alice'), null);
});

test('durable store rejects hostile keys before touching storage', () => {
  const backing = storage();
  const store = createBrowserSimplexStore({ storage: backing, namespace: 'test' });
  assert.throws(() => store.saveQueue('../escape', { rcvId: new Uint8Array([1]) }), /record id/);
  assert.equal(backing.getItem('simplex-web-v1:test:list:queue'), null);
});

test('durable store can remove selected pending tasks without touching others', () => {
  const store = createBrowserSimplexStore({ storage: storage(), namespace: 'pending-delete' });
  store.replacePending([
    { id: 'alice:send:1', payload: { contactId: 'alice', text: 'a' } },
    { id: 'bob:send:1', payload: { contactId: 'bob', text: 'b' } }
  ]);

  const remaining = store.deletePendingWhere((task) => task.payload && task.payload.contactId === 'alice');
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].payload.contactId, 'bob');
  assert.equal(store.listPending().length, 1);
});

test('durable store capped lists keep newest saved record ids visible', () => {
  const store = createBrowserSimplexStore({ storage: storage(), namespace: 'list-cap' });
  for (let i = 0; i < SIMPLEX_STORE_MAX_LIST_ITEMS + 5; i += 1) {
    store.saveContact('contact-' + String(i).padStart(4, '0'), { state: 'active', index: i });
  }

  const listed = store.listContacts();
  assert.equal(listed.length, SIMPLEX_STORE_MAX_LIST_ITEMS);
  assert.equal(listed.some((row) => row.id === 'contact-0000'), false);
  assert.equal(listed.some((row) => row.id === 'contact-1004'), true);
  assert.equal(store.loadContact('contact-1004').index, SIMPLEX_STORE_MAX_LIST_ITEMS + 4);
});

test('durable store deleteWhere scans records beyond the capped visible list', () => {
  const store = createBrowserSimplexStore({ storage: storage(), namespace: 'delete-scan' });
  for (let i = 0; i < SIMPLEX_STORE_MAX_LIST_ITEMS + 5; i += 1) {
    const id = 'rx-' + String(i).padStart(4, '0');
    store.save('received', id, { contactId: i === 0 ? 'alice' : 'bob', index: i });
  }

  assert.equal(store.list('received').some((row) => row.id === 'rx-0000'), false);
  assert.equal(store.load('received', 'rx-0000').contactId, 'alice');
  assert.equal(store.deleteWhere('received', (value) => value.contactId === 'alice'), 1);
  assert.equal(store.load('received', 'rx-0000'), null);
  assert.equal(store.load('received', 'rx-1004').contactId, 'bob');
});

test('durable store deleteWhere ignores malformed storage keys and records', () => {
  const backing = storage();
  const store = createBrowserSimplexStore({ storage: backing, namespace: 'delete-scan-garbage' });
  store.save('received', 'valid-alice', { contactId: 'alice' });
  backing.setItem('simplex-web-v1:delete-scan-garbage:received:../bad', 'not-json');
  backing.setItem('simplex-web-v1:delete-scan-garbage:received:corrupt', 'not-json');

  assert.equal(store.deleteWhere('received', (value) => value.contactId === 'alice'), 1);
  assert.equal(store.load('received', 'valid-alice'), null);
});
