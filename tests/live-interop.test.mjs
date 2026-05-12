// SPDX-License-Identifier: AGPL-3.0-only
//
// Skipped-by-default live interoperability contract.
//
// The normal test suite uses deterministic local servers so it stays reliable
// offline. This file is the release gate for real reviewed browser-profile
// SMP/XFTP endpoints: set SIMPLEX_WEB_LIVE_ENABLE=1 plus the endpoint-specific
// variables documented in docs/LIVE_INTEROP.md, then run `npm run test:live`.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  asciiBytes,
  decodeBase64Url,
  encodeBase64Url,
  encodeSignedTransmission,
  equalBytes,
  hexToBytes,
  utf8Bytes
} from '../src/browser-smp-core.mjs';
import { connectBrowserSmpWebSocketTransport } from '../src/browser-smp-websocket-transport.mjs';
import { createBrowserXftpClient } from '../src/browser-xftp-client.mjs';
import { createBrowserXftpHttpTransport } from '../src/browser-xftp-http-transport.mjs';

const LIVE_ENABLED = process.env.SIMPLEX_WEB_LIVE_ENABLE === '1';

function env(name) {
  return String(process.env[name] || '').trim();
}

function requireLiveEnv(t, names) {
  if (!LIVE_ENABLED) {
    t.skip('set SIMPLEX_WEB_LIVE_ENABLE=1 and live endpoint variables to run this test');
    return false;
  }
  const missing = names.filter((name) => !env(name));
  if (missing.length) {
    throw new Error('missing live interoperability environment variables: ' + missing.join(', '));
  }
  return true;
}

function decodeEnvBytes(name) {
  const value = env(name);
  if (/^[0-9a-f]+$/i.test(value) && value.length % 2 === 0) return hexToBytes(value);
  return decodeBase64Url(value, name);
}

function liveTimeoutMs() {
  const value = Number(env('SIMPLEX_WEB_LIVE_TIMEOUT_MS') || 15000);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 15000;
}

function uniqueLiveId(prefix) {
  const random = Math.random().toString(16).slice(2);
  return prefix + '-' + Date.now().toString(36) + '-' + random;
}

test('live browser SMP WebSocket profile handshakes and answers PING', async (t) => {
  if (!requireLiveEnv(t, [
    'SIMPLEX_WEB_LIVE_SMP_WS_URL',
    'SIMPLEX_WEB_LIVE_SMP_KEY_HASH'
  ])) return;

  const keyHash = decodeEnvBytes('SIMPLEX_WEB_LIVE_SMP_KEY_HASH');
  const expectedSessionId = env('SIMPLEX_WEB_LIVE_SMP_EXPECTED_SESSION_ID')
    ? decodeEnvBytes('SIMPLEX_WEB_LIVE_SMP_EXPECTED_SESSION_ID')
    : undefined;
  const transport = await connectBrowserSmpWebSocketTransport({
    url: env('SIMPLEX_WEB_LIVE_SMP_WS_URL'),
    keyHash,
    expectedSessionId,
    timeoutMs: liveTimeoutMs()
  });

  try {
    assert.equal(transport.profile, 'simplex-smp-websocket-browser-v1');
    assert.equal(transport.security.plaintextBridge, false);
    assert.equal(transport.security.browserNativeProtocol, true);
    assert.equal(transport.security.binarySmpBlocksOnly, true);
    assert.equal(equalBytes(transport.keyHash, keyHash), true);
    if (expectedSessionId) assert.equal(equalBytes(transport.sessionId, expectedSessionId), true);

    const corrId = asciiBytes(uniqueLiveId('live-ping'));
    transport.sendSignedTransmissions([
      encodeSignedTransmission(transport.version, transport.sessionId, {
        signature: new Uint8Array(),
        corrId,
        queueId: new Uint8Array(),
        command: { type: 'PING' }
      })
    ]);
    const [response] = await transport.receiveSignedTransmissions({
      kind: 'broker',
      timeoutMs: liveTimeoutMs()
    });
    assert.equal(response.message.type, 'PONG');
    assert.equal(equalBytes(response.corrId, corrId), true);
  } finally {
    transport.close();
  }
});

test('live browser XFTP HTTPS profile stores encrypted chunks only', async (t) => {
  if (!requireLiveEnv(t, [
    'SIMPLEX_WEB_LIVE_XFTP_HTTP_URL',
    'SIMPLEX_WEB_LIVE_XFTP_KEY_HASH',
    'SIMPLEX_WEB_LIVE_XFTP_ADDRESS',
    'SIMPLEX_WEB_LIVE_XFTP_ORIGIN'
  ])) return;

  const fileId = uniqueLiveId('simplex-web-live-xftp');
  const plaintext = utf8Bytes('simplex-web live xftp interop ' + fileId);
  const client = createBrowserXftpClient({
    server: createBrowserXftpHttpTransport({
      url: env('SIMPLEX_WEB_LIVE_XFTP_HTTP_URL')
    }),
    profile: {
      version: 1,
      transport: 'https',
      url: env('SIMPLEX_WEB_LIVE_XFTP_HTTP_URL'),
      allowedOrigins: [env('SIMPLEX_WEB_LIVE_XFTP_ORIGIN')],
      keyHash: encodeBase64Url(decodeEnvBytes('SIMPLEX_WEB_LIVE_XFTP_KEY_HASH')),
      xftpAddress: env('SIMPLEX_WEB_LIVE_XFTP_ADDRESS'),
      encryptedChunksOnly: true,
      retentionHours: Number(env('SIMPLEX_WEB_LIVE_XFTP_RETENTION_HOURS') || 24)
    }
  });

  const upload = await client.uploadFile(plaintext, {
    fileId,
    name: 'simplex-web-live-interop.txt',
    mime: 'text/plain',
    chunkSize: 1024
  });
  assert.equal(upload.uploadedChunks, upload.manifest.chunkCount);
  assert.equal(upload.manifest.chunks.every((chunk) => chunk.ciphertextSha256), true);
  assert.equal(equalBytes(await client.downloadFile(upload.manifest, upload.rootKey), plaintext), true);
  assert.deepEqual(await client.deleteFile(upload.manifest), { deleted: upload.manifest.chunkCount });
  await assert.rejects(() => client.downloadFile(upload.manifest, upload.rootKey), /status 404/i);
});
