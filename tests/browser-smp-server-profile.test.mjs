import test from 'node:test';
import assert from 'node:assert/strict';

import { encodeBase64Url } from '../src/browser-smp-core.mjs';
import { assertProductionBrowserSmpServerProfile } from '../src/browser-smp-server-profile.mjs';

test('production browser SMP server profile normalizes reviewed websocket profile', () => {
  const profile = assertProductionBrowserSmpServerProfile({
    version: 1,
    transport: 'websocket',
    url: 'wss://smp.example.test/smp#frag',
    allowedOrigins: ['https://app.example.test/path'],
    keyHash: encodeBase64Url(new Uint8Array(32).fill(1)),
    blockSize: 16384,
    binaryFramesOnly: true,
    padding: 'smp-16384',
    sessionBinding: { type: 'signed-handshake' }
  });
  assert.equal(profile.url, 'wss://smp.example.test/smp');
  assert.deepEqual(profile.allowedOrigins, ['https://app.example.test']);
});

test('production browser SMP server profile rejects plaintext and missing binding', () => {
  assert.throws(() => assertProductionBrowserSmpServerProfile({
    version: 1,
    transport: 'websocket',
    url: 'ws://evil.example.test/smp',
    allowedOrigins: ['https://app.example.test'],
    keyHash: encodeBase64Url(new Uint8Array(32).fill(1)),
    sessionBinding: { type: 'signed-handshake' }
  }), /wss/);
  assert.throws(() => assertProductionBrowserSmpServerProfile({
    version: 1,
    transport: 'websocket',
    url: 'wss://smp.example.test/smp',
    allowedOrigins: ['https://app.example.test'],
    keyHash: encodeBase64Url(new Uint8Array(32).fill(1))
  }), /session binding/);
});
