import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import { encodeBase64Url, equalBytes, utf8Bytes } from '../src/browser-smp-core.mjs';
import { createBrowserXftpClient } from '../src/browser-xftp-client.mjs';
import {
  createBrowserXftpHttpTransport,
  normalizeXftpHttpUrl
} from '../src/browser-xftp-http-transport.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function productionProfile(url) {
  return {
    version: 1,
    transport: 'https',
    url: 'https://xftp.example.test/chunks',
    allowedOrigins: ['https://app.example.test'],
    keyHash: encodeBase64Url(filled(32, 101)),
    xftpAddress: 'xftp://fingerprint@xftp.example.test',
    encryptedChunksOnly: true,
    retentionHours: 24,
    testUrl: url
  };
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    var chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('error', reject);
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

function sendJson(response, status, value) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(value || {}));
}

async function withLoopbackXftpHttpServer(fn) {
  var stored = new Map();
  var postedBodies = [];
  var server = http.createServer(async (request, response) => {
    try {
      var url = new URL(request.url, 'http://127.0.0.1');
      if (request.method === 'POST' && url.pathname === '/xftp/chunks') {
        var body = await readRequestBody(request);
        postedBodies.push(body);
        var packet = JSON.parse(body);
        stored.set(packet.fileId + ':' + packet.index, packet);
        sendJson(response, 200, { ok: true });
        return;
      }
      var match = /^\/xftp\/chunks\/([^/]+)\/([^/]+)$/.exec(url.pathname);
      if (match && request.method === 'GET') {
        var packet = stored.get(decodeURIComponent(match[1]) + ':' + Number(decodeURIComponent(match[2])));
        if (!packet) return sendJson(response, 404, { error: 'missing' });
        sendJson(response, 200, packet);
        return;
      }
      if (match && request.method === 'DELETE') {
        stored.delete(decodeURIComponent(match[1]) + ':' + Number(decodeURIComponent(match[2])));
        sendJson(response, 200, { ok: true });
        return;
      }
      sendJson(response, 404, { error: 'not found' });
    } catch (error) {
      sendJson(response, 500, { error: error && error.message || 'error' });
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await fn({
      url: `http://127.0.0.1:${server.address().port}/xftp`,
      stored,
      postedBodies
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('XFTP HTTP URL normalization rejects remote plaintext and allows explicit loopback tests', () => {
  assert.equal(normalizeXftpHttpUrl('https://xftp.example.test/api'), 'https://xftp.example.test/api');
  assert.throws(() => normalizeXftpHttpUrl('http://xftp.example.test/api'), /requires https/i);
  assert.throws(() => normalizeXftpHttpUrl('http://127.0.0.1:8080/api'), /requires https/i);
  assert.equal(normalizeXftpHttpUrl('http://127.0.0.1:8080/api', { allowInsecureLocal: true }), 'http://127.0.0.1:8080/api');
});

test('browser XFTP HTTP transport uploads downloads and deletes encrypted chunks over real fetch', async () => {
  await withLoopbackXftpHttpServer(async ({ url, postedBodies }) => {
    const transport = createBrowserXftpHttpTransport({ url, allowInsecureLocal: true });
    const client = createBrowserXftpClient({
      server: transport,
      profile: productionProfile(url)
    });
    const plaintext = utf8Bytes('http xftp secret '.repeat(80));
    const upload = await client.uploadFile(plaintext, {
      name: '../http.txt',
      mime: 'text/plain',
      fileId: 'http-file-1',
      rootKey: filled(32, 102),
      chunkSize: 1024
    });

    assert.equal(upload.uploadedChunks, upload.manifest.chunkCount);
    assert.equal(postedBodies.some((body) => body.includes('http xftp secret')), false);
    assert.equal(postedBodies.every((body) => body.includes('"ciphertext"') && body.includes('"tag"')), true);
    assert.equal(equalBytes(await client.downloadFile(upload.manifest, upload.rootKey), plaintext), true);

    assert.deepEqual(await client.deleteFile(upload.manifest), { deleted: upload.manifest.chunkCount });
    await assert.rejects(() => client.downloadFile(upload.manifest, upload.rootKey), /status 404/i);
  });
});
