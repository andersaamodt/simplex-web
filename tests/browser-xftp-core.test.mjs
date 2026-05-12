import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import { assembleXftpDownload, createXftpUpload } from '../src/browser-xftp-core.mjs';

test('XFTP upload chunks encrypt and reassemble with manifest checks', () => {
  const file = smp.utf8Bytes('hello xftp '.repeat(200));
  const upload = createXftpUpload(file, {
    rootKey: new Uint8Array(32).fill(1),
    fileId: 'file-1',
    name: '../notes.txt',
    chunkSize: 1024
  });

  const assembled = assembleXftpDownload(upload.manifest, upload.chunks, upload.rootKey);
  assert.equal(smp.utf8Text(assembled), smp.utf8Text(file));
  assert.equal(upload.manifest.name, '.._notes.txt');
});

test('XFTP rejects tampered encrypted chunks', () => {
  const upload = createXftpUpload(smp.utf8Bytes('secret'), {
    rootKey: new Uint8Array(32).fill(2),
    fileId: 'file-2',
    chunkSize: 1024
  });
  upload.chunks[0].ciphertext[0] ^= 1;
  assert.throws(() => assembleXftpDownload(upload.manifest, upload.chunks, upload.rootKey), /decryption failed|hash/i);
});
