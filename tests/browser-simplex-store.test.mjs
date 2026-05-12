import test from 'node:test';
import assert from 'node:assert/strict';

import { createBrowserSimplexStore } from '../src/browser-simplex-store.mjs';

function storage() {
  const map = new Map();
  return {
    getItem(key) { return map.has(key) ? map.get(key) : null; },
    setItem(key, value) { map.set(String(key), String(value)); },
    removeItem(key) { map.delete(String(key)); }
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
});

test('durable store rejects hostile keys before touching storage', () => {
  const backing = storage();
  const store = createBrowserSimplexStore({ storage: backing, namespace: 'test' });
  assert.throws(() => store.saveQueue('../escape', { rcvId: new Uint8Array([1]) }), /record id/);
  assert.equal(backing.getItem('simplex-web-v1:test:list:queue'), null);
});
