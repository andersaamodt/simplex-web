// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser XFTP-over-HTTPS encrypted chunk transport.
//
// This is a small browser profile for storing already-encrypted XFTP chunks
// over `fetch`. It does not know plaintext file bytes or root keys. The server
// receives JSON metadata plus base64url ciphertext/tag fields and returns the
// same encrypted packet shape for download verification by `browser-xftp-client`.

import { decodeBase64Url, encodeBase64Url, toBytes } from './browser-smp-core.mjs';

export class BrowserXftpHttpTransportError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserXftpHttpTransportError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserXftpHttpTransportError(code, message);
}

function isLoopbackHost(hostname) {
  var host = String(hostname || '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

export function normalizeXftpHttpUrl(value, options = {}) {
  var raw = String(value || '').trim();
  if (!raw) fail('XFTP_HTTP_URL', 'XFTP HTTP transport URL is required');
  var parsed;
  try {
    parsed = new URL(raw, globalThis.location && globalThis.location.href || 'https://example.invalid/');
  } catch (_error) {
    fail('XFTP_HTTP_URL', 'XFTP HTTP transport URL is invalid');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    fail('XFTP_HTTP_URL', 'XFTP HTTP transport requires https://');
  }
  if (parsed.protocol === 'http:' && (!isLoopbackHost(parsed.hostname) || options.allowInsecureLocal !== true)) {
    fail('XFTP_HTTP_SECURITY', 'XFTP HTTP transport requires https:// outside explicit loopback tests');
  }
  parsed.username = '';
  parsed.password = '';
  parsed.hash = '';
  parsed.pathname = parsed.pathname.replace(/\/+$/, '') || '/';
  return parsed.href;
}

function endpoint(baseUrl, fileId, index) {
  var base = new URL(baseUrl);
  var path = base.pathname.replace(/\/+$/, '');
  if (fileId == null) {
    base.pathname = path + '/chunks';
  } else {
    base.pathname = path + '/chunks/' + encodeURIComponent(String(fileId)) + '/' + encodeURIComponent(String(index));
  }
  return base.href;
}

function packetToJson(packet) {
  return {
    fileId: String(packet.fileId || ''),
    index: Number(packet.index),
    size: Number(packet.size),
    sha256: String(packet.sha256 || ''),
    ciphertext: encodeBase64Url(packet.ciphertext || new Uint8Array()),
    tag: encodeBase64Url(packet.tag || new Uint8Array()),
    ciphertextSha256: String(packet.ciphertextSha256 || '')
  };
}

function packetFromJson(value) {
  var packet = value && typeof value === 'object' ? value : {};
  return {
    fileId: String(packet.fileId || ''),
    index: Number(packet.index),
    size: Number(packet.size),
    sha256: String(packet.sha256 || ''),
    ciphertext: decodeBase64Url(packet.ciphertext, 'XFTP chunk ciphertext'),
    tag: decodeBase64Url(packet.tag, 'XFTP chunk tag'),
    ciphertextSha256: String(packet.ciphertextSha256 || '')
  };
}

async function readJson(response) {
  var text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (_error) {
    fail('XFTP_HTTP_JSON', 'XFTP HTTP transport received invalid JSON');
  }
}

async function requestJson(fetchImpl, url, options = {}) {
  var response = await fetchImpl(url, options);
  if (!response || typeof response.ok !== 'boolean') fail('XFTP_HTTP_FETCH', 'XFTP HTTP transport returned an invalid response');
  if (!response.ok) fail('XFTP_HTTP_STATUS', 'XFTP HTTP transport status ' + response.status);
  return readJson(response);
}

export function createBrowserXftpHttpTransport(options = {}) {
  return new BrowserXftpHttpTransport(options);
}

export class BrowserXftpHttpTransport {
  constructor(options = {}) {
    this.url = normalizeXftpHttpUrl(options.url, options);
    this.fetch = options.fetchImpl || globalThis.fetch;
    if (typeof this.fetch !== 'function') fail('XFTP_HTTP_FETCH', 'fetch is not available');
    this.headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };
  }

  async putChunk(packet) {
    var payload = packetToJson(packet || {});
    if (!payload.fileId) fail('XFTP_HTTP_PACKET', 'XFTP chunk file id is required');
    await requestJson(this.fetch, endpoint(this.url), {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(payload)
    });
    return { ok: true };
  }

  async getChunk(fileId, index) {
    var data = await requestJson(this.fetch, endpoint(this.url, fileId, index), {
      method: 'GET',
      headers: { Accept: 'application/json' }
    });
    return packetFromJson(data);
  }

  async deleteChunk(fileId, index) {
    await requestJson(this.fetch, endpoint(this.url, fileId, index), {
      method: 'DELETE',
      headers: { Accept: 'application/json' }
    });
    return { ok: true };
  }
}

export default {
  BrowserXftpHttpTransport,
  BrowserXftpHttpTransportError,
  createBrowserXftpHttpTransport,
  normalizeXftpHttpUrl
};
