import test from 'node:test';
import assert from 'node:assert/strict';

import { encodeBase64Url } from '../src/browser-smp-core.mjs';
import {
  assertProductionBrowserXftpServerProfile,
  normalizeBrowserXftpServerProfile,
  parseXftpServerAddress
} from '../src/browser-xftp-server-profile.mjs';

function keyHash(seed) {
  return encodeBase64Url(new Uint8Array(32).fill(seed));
}

test('browser XFTP server address parser preserves fingerprint, password, and onion host', () => {
  const parsed = parseXftpServerAddress('xftp://fingerprint:password@xftp.example.test,onion.example.onion');
  assert.equal(parsed.fingerprint, 'fingerprint');
  assert.equal(parsed.password, 'password');
  assert.equal(parsed.host, 'xftp.example.test');
  assert.equal(parsed.onionHost, 'onion.example.onion');
});

test('production browser XFTP server profile normalizes reviewed websocket profile', () => {
  const profile = assertProductionBrowserXftpServerProfile({
    version: 1,
    transport: 'websocket',
    url: 'wss://xftp.example.test/upload#frag',
    allowedOrigins: ['https://app.example.test/path'],
    keyHash: keyHash(7),
    xftpAddress: 'xftp://fingerprint@xftp.example.test',
    encryptedChunksOnly: true,
    retentionHours: 24
  });
  assert.equal(profile.url, 'wss://xftp.example.test/upload');
  assert.deepEqual(profile.allowedOrigins, ['https://app.example.test']);
  assert.equal(profile.xftpAddress.host, 'xftp.example.test');
  assert.equal(profile.encryptedChunksOnly, true);
});

test('browser XFTP server profile derives an xftp address from the key hash when omitted', () => {
  const profile = normalizeBrowserXftpServerProfile({
    version: 1,
    transport: 'https',
    url: 'https://xftp.example.test/chunks',
    keyHash: keyHash(8)
  });
  assert.equal(profile.xftpAddress.fingerprint, profile.keyHashBase64Url);
  assert.equal(profile.xftpAddress.host, 'xftp.example.test');
});

test('production browser XFTP server profile rejects plaintext, missing origin, and long retention', () => {
  assert.throws(() => assertProductionBrowserXftpServerProfile({
    version: 1,
    transport: 'websocket',
    url: 'ws://xftp.example.test/upload',
    allowedOrigins: ['https://app.example.test'],
    keyHash: keyHash(1),
    xftpAddress: 'xftp://fingerprint@xftp.example.test'
  }), /https|wss/i);

  assert.throws(() => assertProductionBrowserXftpServerProfile({
    version: 1,
    transport: 'websocket',
    url: 'wss://xftp.example.test/upload',
    keyHash: keyHash(1),
    xftpAddress: 'xftp://fingerprint@xftp.example.test'
  }), /origin/i);

  assert.throws(() => assertProductionBrowserXftpServerProfile({
    version: 1,
    transport: 'websocket',
    url: 'wss://xftp.example.test/upload',
    allowedOrigins: ['https://app.example.test'],
    keyHash: keyHash(1),
    xftpAddress: 'xftp://fingerprint@xftp.example.test',
    retentionHours: 999
  }), /retention/i);
});

test('browser XFTP server profile rejects unsafe xftp addresses', () => {
  assert.throws(() => parseXftpServerAddress('xftp://finger print@host'), /address/i);
  assert.throws(() => parseXftpServerAddress('https://fingerprint@host'), /xftp/i);
  assert.throws(() => parseXftpServerAddress('xftp://fingerprint@host\nforged'), /control|whitespace/i);
  assert.throws(() => parseXftpServerAddress('xftp://fingerprint@host/path'), /address/i);
});
