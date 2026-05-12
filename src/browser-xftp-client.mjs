// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser XFTP client over an abstract encrypted-chunk transport.
//
// `browser-xftp-core.mjs` prepares encrypted chunks and verifies downloads.
// This module owns upload/download sequencing and profile checks. It never
// exposes plaintext to the server transport; the server sees only manifest
// metadata and encrypted chunk packets.

import { bytesToHex, concatBytes, sha256Hash, toBytes } from './browser-smp-core.mjs';
import { assembleXftpDownload, createXftpUpload } from './browser-xftp-core.mjs';
import { assertProductionBrowserXftpServerProfile } from './browser-xftp-server-profile.mjs';

export class BrowserXftpClientError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserXftpClientError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserXftpClientError(code, message);
}

function requireServer(server) {
  if (!server || typeof server.putChunk !== 'function' || typeof server.getChunk !== 'function') {
    fail('XFTP_CLIENT_SERVER', 'browser XFTP client requires putChunk/getChunk server methods');
  }
  return server;
}

function chunkPacket(fileId, chunk) {
  return {
    fileId,
    index: chunk.index,
    size: chunk.size,
    sha256: chunk.sha256,
    ciphertext: chunk.ciphertext,
    tag: chunk.tag,
    ciphertextSha256: bytesToHex(sha256Hash(concatBytes(chunk.ciphertext, chunk.tag)))
  };
}

function normalizeChunkResponse(response, expected) {
  var chunk = response && typeof response === 'object' ? response : {};
  if (Number(chunk.index) !== Number(expected.index)) fail('XFTP_CLIENT_CHUNK', 'downloaded chunk index mismatch');
  if (chunk.ciphertextSha256) {
    var digest = bytesToHex(sha256Hash(concatBytes(chunk.ciphertext || new Uint8Array(), chunk.tag || new Uint8Array())));
    if (digest !== chunk.ciphertextSha256) fail('XFTP_CLIENT_CHUNK', 'downloaded chunk ciphertext hash mismatch');
  }
  return {
    index: Number(chunk.index),
    size: Number(chunk.size),
    sha256: String(chunk.sha256 || expected.sha256 || ''),
    ciphertext: toBytes(chunk.ciphertext || new Uint8Array(), 'downloaded chunk ciphertext'),
    tag: toBytes(chunk.tag || new Uint8Array(), 'downloaded chunk tag')
  };
}

export function createBrowserXftpClient(options = {}) {
  return new BrowserXftpClient(options);
}

export class BrowserXftpClient {
  constructor(options = {}) {
    this.server = requireServer(options.server);
    this.profile = options.profile ? assertProductionBrowserXftpServerProfile(options.profile) : null;
  }

  async uploadFile(bytes, options = {}) {
    if (options.profile) this.profile = assertProductionBrowserXftpServerProfile(options.profile);
    var upload = createXftpUpload(bytes, options);
    var stored = [];
    for (var chunk of upload.chunks) {
      var packet = chunkPacket(upload.manifest.fileId, chunk);
      await this.server.putChunk(packet, { profile: this.profile });
      stored.push({
        index: packet.index,
        size: packet.size,
        sha256: packet.sha256,
        ciphertextSha256: packet.ciphertextSha256
      });
    }
    return {
      manifest: { ...upload.manifest, chunks: stored },
      rootKey: upload.rootKey,
      uploadedChunks: stored.length,
      profile: this.profile
    };
  }

  async downloadFile(manifest, rootKey, options = {}) {
    if (options.profile) this.profile = assertProductionBrowserXftpServerProfile(options.profile);
    var m = manifest && typeof manifest === 'object' ? manifest : {};
    var expected = Array.isArray(m.chunks) ? m.chunks : [];
    if (!expected.length || Number(m.chunkCount) !== expected.length) fail('XFTP_CLIENT_MANIFEST', 'XFTP manifest chunk list is incomplete');
    var chunks = [];
    for (var chunkRef of expected.slice().sort((a, b) => Number(a.index) - Number(b.index))) {
      var response = await this.server.getChunk(m.fileId, Number(chunkRef.index), { profile: this.profile });
      chunks.push(normalizeChunkResponse(response, chunkRef));
    }
    return assembleXftpDownload(m, chunks, rootKey);
  }

  async deleteFile(manifest, options = {}) {
    if (typeof this.server.deleteChunk !== 'function') return { deleted: 0 };
    var refs = manifest && Array.isArray(manifest.chunks) ? manifest.chunks : [];
    var deleted = 0;
    for (var chunkRef of refs) {
      await this.server.deleteChunk(manifest.fileId, Number(chunkRef.index), options);
      deleted += 1;
    }
    return { deleted };
  }
}

export default {
  BrowserXftpClient,
  BrowserXftpClientError,
  createBrowserXftpClient
};
