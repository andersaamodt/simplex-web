// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser XFTP core helpers.
//
// This module owns file chunking, manifest creation, chunk authentication, and
// reassembly checks. It deliberately does not hide transport behind a hosted
// bridge: callers provide bytes and move encrypted chunks over a reviewed XFTP
// server/profile layer.

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  asciiBytes,
  bytesToHex,
  concatBytes,
  decryptAesGcm,
  encodeBase64Url,
  encryptAesGcm,
  randomBytes32,
  sha256Hash,
  toBytes,
  utf8Bytes
} from './browser-smp-core.mjs';

export const XFTP_MANIFEST_VERSION = 1;
export const XFTP_DEFAULT_CHUNK_SIZE = 65536;
export const XFTP_MAX_CHUNK_SIZE = 1048576;
export const XFTP_MAX_CHUNKS = 20000;

export class BrowserXftpError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserXftpError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserXftpError(code, message);
}

function chunkSize(value) {
  var size = Math.floor(Number(value || XFTP_DEFAULT_CHUNK_SIZE));
  if (!Number.isSafeInteger(size) || size < 1024 || size > XFTP_MAX_CHUNK_SIZE) fail('XFTP_CHUNK_SIZE', 'XFTP chunk size is invalid');
  return size;
}

function deriveChunkKey(rootKey, fileId, index) {
  return hkdf(sha256, toBytes(rootKey, 'XFTP root key'), utf8Bytes(fileId), asciiBytes('simplex-web xftp chunk ' + index), 32);
}

function deriveChunkIv(fileId, index) {
  return sha256Hash(concatBytes(utf8Bytes(fileId), asciiBytes(':' + index))).slice(0, 12);
}

function cleanName(value) {
  return String(value || 'file').replace(/[^\w .-]/g, '_').slice(0, 180) || 'file';
}

export function encryptXftpChunk(options = {}) {
  var index = Math.max(0, Math.floor(Number(options.index || 0)));
  var fileId = String(options.fileId || '');
  if (!fileId) fail('XFTP_FILE_ID', 'file id is required');
  var plaintext = toBytes(options.plaintext || new Uint8Array(), 'chunk plaintext');
  var key = deriveChunkKey(options.rootKey, fileId, index);
  var iv = deriveChunkIv(fileId, index);
  var aad = utf8Bytes(JSON.stringify({ v: XFTP_MANIFEST_VERSION, fileId, index }));
  var encrypted = encryptAesGcm(key, iv, plaintext, Math.max(plaintext.length + 2, 32), aad);
  return {
    index,
    size: plaintext.length,
    sha256: bytesToHex(sha256Hash(plaintext)),
    ciphertext: encrypted.ciphertext,
    tag: encrypted.tag
  };
}

export function decryptXftpChunk(options = {}) {
  var chunk = options.chunk && typeof options.chunk === 'object' ? options.chunk : {};
  var fileId = String(options.fileId || '');
  var index = Math.max(0, Math.floor(Number(chunk.index || 0)));
  var key = deriveChunkKey(options.rootKey, fileId, index);
  var iv = deriveChunkIv(fileId, index);
  var aad = utf8Bytes(JSON.stringify({ v: XFTP_MANIFEST_VERSION, fileId, index }));
  var plaintext = decryptAesGcm(key, iv, chunk.ciphertext, chunk.tag, aad);
  if (chunk.sha256 && bytesToHex(sha256Hash(plaintext)) !== chunk.sha256) fail('XFTP_HASH', 'XFTP chunk hash mismatch');
  if (Number(chunk.size) !== plaintext.length) fail('XFTP_SIZE', 'XFTP chunk size mismatch');
  return plaintext;
}

export function createXftpUpload(bytes, options = {}) {
  var fileBytes = toBytes(bytes || new Uint8Array(), 'XFTP file bytes');
  var size = chunkSize(options.chunkSize);
  var count = Math.ceil(fileBytes.length / size) || 1;
  if (count > XFTP_MAX_CHUNKS) fail('XFTP_CHUNKS', 'XFTP file has too many chunks');
  var rootKey = options.rootKey ? toBytes(options.rootKey, 'XFTP root key') : randomBytes32();
  var fileId = options.fileId || encodeBase64Url(sha256Hash(concatBytes(rootKey, fileBytes, utf8Bytes(String(Date.now()))))).slice(0, 32);
  var chunks = [];
  for (var i = 0; i < count; i += 1) {
    chunks.push(encryptXftpChunk({
      rootKey,
      fileId,
      index: i,
      plaintext: fileBytes.slice(i * size, Math.min(fileBytes.length, (i + 1) * size))
    }));
  }
  var manifest = {
    version: XFTP_MANIFEST_VERSION,
    fileId,
    name: cleanName(options.name),
    mime: String(options.mime || 'application/octet-stream').slice(0, 120),
    size: fileBytes.length,
    chunkSize: size,
    chunkCount: chunks.length,
    sha256: bytesToHex(sha256Hash(fileBytes)),
    chunks: chunks.map((chunk) => ({
      index: chunk.index,
      size: chunk.size,
      sha256: chunk.sha256,
      ciphertextSha256: bytesToHex(sha256Hash(concatBytes(chunk.ciphertext, chunk.tag)))
    }))
  };
  return { rootKey, manifest, chunks };
}

export function assembleXftpDownload(manifest, chunks, rootKey) {
  var m = manifest && typeof manifest === 'object' ? manifest : {};
  if (m.version !== XFTP_MANIFEST_VERSION) fail('XFTP_MANIFEST', 'XFTP manifest version is unsupported');
  var sorted = (Array.isArray(chunks) ? chunks : []).slice().sort((a, b) => Number(a.index) - Number(b.index));
  if (sorted.length !== Number(m.chunkCount)) fail('XFTP_MANIFEST', 'XFTP chunk count mismatch');
  var plaintext = [];
  for (var i = 0; i < sorted.length; i += 1) {
    if (Number(sorted[i].index) !== i) fail('XFTP_MANIFEST', 'XFTP chunks are not contiguous');
    plaintext.push(decryptXftpChunk({ rootKey, fileId: m.fileId, chunk: sorted[i] }));
  }
  var file = concatBytes(...plaintext);
  if (file.length !== Number(m.size)) fail('XFTP_SIZE', 'XFTP file size mismatch');
  if (bytesToHex(sha256Hash(file)) !== m.sha256) fail('XFTP_HASH', 'XFTP file hash mismatch');
  return file;
}

export default {
  BrowserXftpError,
  XFTP_MANIFEST_VERSION,
  assembleXftpDownload,
  createXftpUpload,
  decryptXftpChunk,
  encryptXftpChunk
};
