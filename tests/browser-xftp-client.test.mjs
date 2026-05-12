import test from 'node:test';
import assert from 'node:assert/strict';

import { encodeBase64Url, equalBytes, utf8Bytes } from '../src/browser-smp-core.mjs';
import { createBrowserXftpClient } from '../src/browser-xftp-client.mjs';

function profile() {
  return {
    version: 1,
    transport: 'websocket',
    url: 'wss://xftp.example.test/upload',
    allowedOrigins: ['https://app.example.test'],
    keyHash: encodeBase64Url(new Uint8Array(32).fill(9)),
    xftpAddress: 'xftp://fingerprint@xftp.example.test',
    encryptedChunksOnly: true,
    retentionHours: 24
  };
}

function createMemoryEncryptedChunkServer() {
  const chunks = new Map();
  const puts = [];
  return {
    puts,
    async putChunk(packet, context) {
      assert.ok(context.profile, 'profile is passed to the XFTP server boundary');
      assert.equal(packet.fileId.length > 0, true);
      assert.ok(packet.ciphertext instanceof Uint8Array);
      assert.ok(packet.tag instanceof Uint8Array);
      puts.push(packet);
      chunks.set(packet.fileId + ':' + packet.index, {
        index: packet.index,
        size: packet.size,
        sha256: packet.sha256,
        ciphertext: new Uint8Array(packet.ciphertext),
        tag: new Uint8Array(packet.tag),
        ciphertextSha256: packet.ciphertextSha256
      });
      return { ok: true };
    },
    async getChunk(fileId, index) {
      const chunk = chunks.get(fileId + ':' + index);
      if (!chunk) throw new Error('missing chunk');
      return {
        ...chunk,
        ciphertext: new Uint8Array(chunk.ciphertext),
        tag: new Uint8Array(chunk.tag)
      };
    },
    async deleteChunk(fileId, index) {
      chunks.delete(fileId + ':' + index);
    },
    tamperFirstChunk(fileId) {
      const chunk = chunks.get(fileId + ':0');
      chunk.ciphertext[0] ^= 1;
    }
  };
}

test('browser XFTP client uploads encrypted chunks and downloads verified plaintext', async () => {
  const server = createMemoryEncryptedChunkServer();
  const client = createBrowserXftpClient({ server, profile: profile() });
  const plaintext = utf8Bytes('browser xftp secret '.repeat(100));
  const result = await client.uploadFile(plaintext, {
    name: '../secret.txt',
    mime: 'text/plain',
    chunkSize: 1024,
    fileId: 'file-client-1',
    rootKey: new Uint8Array(32).fill(11)
  });

  assert.equal(result.manifest.name, '.._secret.txt');
  assert.equal(result.uploadedChunks, result.manifest.chunkCount);
  const marker = Buffer.from('browser xftp secret');
  assert.equal(server.puts.some((packet) => Buffer.from(packet.ciphertext).includes(marker)), false);

  const downloaded = await client.downloadFile(result.manifest, result.rootKey);
  assert.equal(equalBytes(downloaded, plaintext), true);
});

test('browser XFTP client rejects tampered downloaded chunks before returning plaintext', async () => {
  const server = createMemoryEncryptedChunkServer();
  const client = createBrowserXftpClient({ server, profile: profile() });
  const upload = await client.uploadFile(utf8Bytes('tamper target'), {
    chunkSize: 1024,
    fileId: 'file-client-2',
    rootKey: new Uint8Array(32).fill(12)
  });

  server.tamperFirstChunk(upload.manifest.fileId);
  await assert.rejects(() => client.downloadFile(upload.manifest, upload.rootKey), /ciphertext hash|decryption failed|hash/i);
});

test('browser XFTP client rejects incomplete manifests and downgraded profiles', async () => {
  const server = createMemoryEncryptedChunkServer();
  const client = createBrowserXftpClient({ server, profile: profile() });

  await assert.rejects(() => client.downloadFile({ version: 1, fileId: 'missing', chunkCount: 1 }, new Uint8Array(32)), /manifest/i);
  assert.throws(() => createBrowserXftpClient({
    server,
    profile: {
      ...profile(),
      url: 'http://xftp.example.test/upload'
    }
  }), /https|wss/i);
});

test('browser XFTP client deletes remote encrypted chunks when the server supports deletion', async () => {
  const server = createMemoryEncryptedChunkServer();
  const client = createBrowserXftpClient({ server, profile: profile() });
  const upload = await client.uploadFile(utf8Bytes('delete me'), {
    chunkSize: 1024,
    fileId: 'file-client-3',
    rootKey: new Uint8Array(32).fill(13)
  });

  assert.deepEqual(await client.deleteFile(upload.manifest), { deleted: 1 });
  await assert.rejects(() => client.downloadFile(upload.manifest, upload.rootKey), /missing chunk/i);
});
