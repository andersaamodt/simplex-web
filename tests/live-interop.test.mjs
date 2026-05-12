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
  encodeSignedTransmission,
  equalBytes,
  generateEd25519KeyPair,
  hexToBytes,
  sha256Hash,
  utf8Bytes
} from '../src/browser-smp-core.mjs';
import { connectBrowserSmpWebSocketTransport } from '../src/browser-smp-websocket-transport.mjs';
import {
  connectBrowserXftpWebClient,
  createXftpWebFile,
  deleteXftpWebFile,
  downloadXftpWebFileChunk,
  pingXftpWeb,
  putXftpWebFile
} from '../src/browser-xftp-web-client.mjs';

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

test('live browser XFTP web profile handshakes verifies identity and answers PING', async (t) => {
  if (!requireLiveEnv(t, [
    'SIMPLEX_WEB_LIVE_XFTP_WEB_URL',
    'SIMPLEX_WEB_LIVE_XFTP_KEY_HASH'
  ])) return;

  const keyHash = decodeEnvBytes('SIMPLEX_WEB_LIVE_XFTP_KEY_HASH');
  const client = await connectBrowserXftpWebClient({
    url: env('SIMPLEX_WEB_LIVE_XFTP_WEB_URL'),
    keyHash,
    timeoutMs: liveTimeoutMs()
  });
  assert.equal(client.profile, 'simplex-xftp-web-browser-v1');
  assert.equal(client.security.plaintextBridge, false);
  assert.equal(client.security.browserNativeProtocol, true);
  assert.equal(client.security.binaryXftpBlocksOnly, true);
  assert.equal(client.security.serverIdentityProof, true);
  assert.equal(equalBytes(client.keyHash, keyHash), true);
  const response = await pingXftpWeb(client);
  assert.equal(response.response.type, 'PONG');
});

test('live browser XFTP web profile creates uploads downloads and deletes a disposable chunk', async (t) => {
  if (!requireLiveEnv(t, [
    'SIMPLEX_WEB_LIVE_XFTP_WEB_URL',
    'SIMPLEX_WEB_LIVE_XFTP_KEY_HASH'
  ])) return;
  if (env('SIMPLEX_WEB_LIVE_XFTP_DESTRUCTIVE') !== '1') {
    t.skip('set SIMPLEX_WEB_LIVE_XFTP_DESTRUCTIVE=1 to run disposable live XFTP file-command interop');
    return;
  }

  const keyHash = decodeEnvBytes('SIMPLEX_WEB_LIVE_XFTP_KEY_HASH');
  const client = await connectBrowserXftpWebClient({
    url: env('SIMPLEX_WEB_LIVE_XFTP_WEB_URL'),
    keyHash,
    timeoutMs: liveTimeoutMs()
  });
  const sender = generateEd25519KeyPair();
  const recipient = generateEd25519KeyPair();
  const chunk = utf8Bytes('simplex-web live xftp web chunk ' + uniqueLiveId('xftp-web'));
  const digest = sha256Hash(chunk);
  let created = null;
  let primaryError = null;
  try {
    created = await createXftpWebFile(client, {
      privateKey: sender.secretKey,
      fileInfo: {
        sndKey: sender.publicKeyDer,
        size: chunk.length,
        digest
      },
      recipientKeys: [recipient.publicKeyDer]
    });
    await putXftpWebFile(client, {
      privateKey: sender.secretKey,
      senderId: created.senderId,
      body: chunk
    });
    const downloaded = await downloadXftpWebFileChunk(client, {
      privateKey: recipient.secretKey,
      recipientId: created.recipientIds[0],
      digest
    });
    assert.equal(equalBytes(downloaded.plaintext, chunk), true);
  } catch (error) {
    primaryError = error;
  } finally {
    if (created) {
      try {
        await deleteXftpWebFile(client, {
          privateKey: sender.secretKey,
          senderId: created.senderId
        });
      } catch (deleteError) {
        if (!primaryError) primaryError = deleteError;
      }
    }
  }
  if (primaryError) throw primaryError;
});
