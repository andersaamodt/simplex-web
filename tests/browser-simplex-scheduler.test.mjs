import test from 'node:test';
import assert from 'node:assert/strict';

import { createBrowserSimplexRetryScheduler, nextRetryDelay } from '../src/browser-simplex-scheduler.mjs';

test('retry scheduler persists due failed and completed tasks', () => {
  let now = 1000;
  const scheduler = createBrowserSimplexRetryScheduler({ clock: { now: () => now }, random: () => 0.5, baseMs: 10, maxMs: 100 });
  scheduler.enqueue('send-1', { text: 'hello' });
  assert.equal(scheduler.due(1000).length, 1);
  const failed = scheduler.fail('send-1', new Error('offline'));
  assert.equal(failed.attempts, 1);
  assert.equal(scheduler.due(now).length, 0);
  now = failed.nextAttemptAt;
  assert.equal(scheduler.due(now).length, 1);
  scheduler.complete('send-1');
  assert.equal(scheduler.due(now).length, 0);
});

test('retry delay is bounded with deterministic jitter', () => {
  assert.equal(nextRetryDelay(0, { baseMs: 100, maxMs: 1000, jitter: 0, random: () => 0 }), 100);
  assert.equal(nextRetryDelay(10, { baseMs: 100, maxMs: 1000, jitter: 0, random: () => 0 }), 1000);
});

test('retry scheduler removes selected durable tasks', () => {
  const scheduler = createBrowserSimplexRetryScheduler();
  scheduler.enqueue('alice-send', { contactId: 'alice' });
  scheduler.enqueue('bob-send', { contactId: 'bob' });

  const remaining = scheduler.removeWhere((task) => task.payload && task.payload.contactId === 'alice');
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].payload.contactId, 'bob');
});
