// SPDX-License-Identifier: AGPL-3.0-only
//
// Retry scheduler for browser SimpleX work.
//
// The scheduler is deterministic unless a caller injects `random()`. It stores
// plain task records and computes the next eligible attempt with bounded
// exponential backoff, jitter, and a maximum retry count.

export const SIMPLEX_RETRY_BASE_MS = 500;
export const SIMPLEX_RETRY_MAX_MS = 30000;
export const SIMPLEX_RETRY_MAX_ATTEMPTS = 12;

export class BrowserSimplexSchedulerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSimplexSchedulerError';
    this.code = code;
  }
}

function safeId(value) {
  var text = String(value == null ? '' : value).trim();
  if (!text || text.length > 160 || /[^A-Za-z0-9_.:-]/.test(text)) {
    throw new BrowserSimplexSchedulerError('SIMPLEX_SCHEDULER_ID', 'task id is invalid');
  }
  return text;
}

function nowMs(clock) {
  return Math.max(0, Math.floor(Number(clock && clock.now ? clock.now() : Date.now()) || 0));
}

export function nextRetryDelay(attempts, options = {}) {
  var base = Math.max(1, Math.floor(Number(options.baseMs || SIMPLEX_RETRY_BASE_MS)));
  var max = Math.max(base, Math.floor(Number(options.maxMs || SIMPLEX_RETRY_MAX_MS)));
  var jitter = Math.max(0, Math.min(1, Number(options.jitter == null ? 0.2 : options.jitter)));
  var exp = Math.min(max, base * Math.pow(2, Math.max(0, Math.floor(Number(attempts || 0)))));
  var random = typeof options.random === 'function' ? options.random() : 0.5;
  var spread = exp * jitter;
  return Math.max(1, Math.floor(exp - spread + (spread * 2 * Math.max(0, Math.min(1, random)))));
}

export function createRetryTask(id, payload = {}, options = {}) {
  var createdAt = nowMs(options.clock);
  return {
    id: safeId(id),
    payload,
    attempts: 0,
    createdAt,
    updatedAt: createdAt,
    nextAttemptAt: createdAt,
    lastError: ''
  };
}

export function markTaskFailure(task, error, options = {}) {
  var t = task && typeof task === 'object' ? task : createRetryTask('task');
  var attempts = Math.max(0, Math.floor(Number(t.attempts || 0))) + 1;
  var updatedAt = nowMs(options.clock);
  return {
    ...t,
    attempts,
    updatedAt,
    nextAttemptAt: updatedAt + nextRetryDelay(attempts, options),
    lastError: String(error && error.message || error || '').slice(0, 500)
  };
}

export function markTaskSuccess(task, options = {}) {
  return { ...(task || {}), completedAt: nowMs(options.clock), lastError: '' };
}

export class BrowserSimplexRetryScheduler {
  constructor(options = {}) {
    this.store = options.store || null;
    this.clock = options.clock || null;
    this.options = options;
    this.tasks = [];
  }

  load() {
    this.tasks = this.store && typeof this.store.listPending === 'function' ? this.store.listPending() : this.tasks;
    return this.tasks;
  }

  save() {
    if (this.store && typeof this.store.replacePending === 'function') this.store.replacePending(this.tasks);
  }

  enqueue(id, payload = {}) {
    var task = createRetryTask(id, payload, { clock: this.clock });
    this.load();
    this.tasks = this.tasks.filter((item) => item.id !== task.id).concat(task);
    this.save();
    return task;
  }

  due(now = nowMs(this.clock)) {
    this.load();
    return this.tasks.filter((task) => !task.completedAt && Math.floor(Number(task.nextAttemptAt || 0)) <= now);
  }

  fail(id, error) {
    var cleanId = safeId(id);
    this.load();
    this.tasks = this.tasks.map((task) => task.id === cleanId ? markTaskFailure(task, error, { ...this.options, clock: this.clock }) : task);
    this.save();
    return this.tasks.find((task) => task.id === cleanId);
  }

  complete(id) {
    var cleanId = safeId(id);
    this.load();
    this.tasks = this.tasks.map((task) => task.id === cleanId ? markTaskSuccess(task, { clock: this.clock }) : task);
    this.save();
    return this.tasks.find((task) => task.id === cleanId);
  }

  prune() {
    this.load();
    var maxAttempts = Math.max(1, Math.floor(Number(this.options.maxAttempts || SIMPLEX_RETRY_MAX_ATTEMPTS)));
    this.tasks = this.tasks.filter((task) => !task.completedAt && Math.floor(Number(task.attempts || 0)) < maxAttempts);
    this.save();
    return this.tasks;
  }
}

export function createBrowserSimplexRetryScheduler(options = {}) {
  return new BrowserSimplexRetryScheduler(options);
}

export default {
  BrowserSimplexRetryScheduler,
  createBrowserSimplexRetryScheduler,
  createRetryTask,
  markTaskFailure,
  markTaskSuccess,
  nextRetryDelay
};
