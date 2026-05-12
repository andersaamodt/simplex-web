// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser XFTP server profile validation.
//
// Native XFTP servers are addressed as `xftp://fingerprint[:password]@host`.
// Browser JavaScript still needs an HTTPS/WebSocket/WebTransport profile to
// move encrypted chunks without raw TCP access. This module validates that
// browser profile before the XFTP client is allowed to upload or download.

import { decodeBase64Url, encodeBase64Url, toBytes } from './browser-smp-core.mjs';

export const SIMPLEX_BROWSER_XFTP_PROFILE_VERSION = 1;
export const SIMPLEX_BROWSER_XFTP_TRANSPORTS = Object.freeze(['https', 'websocket', 'webtransport']);

export class BrowserXftpServerProfileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserXftpServerProfileError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserXftpServerProfileError(code, message);
}

export function parseXftpServerAddress(value) {
  var text = String(value == null ? '' : value).trim();
  if (/[\x00-\x20\x7f]/.test(text)) fail('XFTP_SERVER_ADDRESS', 'XFTP server address contains control or whitespace characters');
  var match = /^xftp:\/\/([^:@,/?#]+)(?::([^@,/?#]+))?@([^,/?#]+)(?:,([^,/?#]+))?$/.exec(text);
  if (!match) fail('XFTP_SERVER_ADDRESS', 'XFTP server address must be xftp://fingerprint[:password]@host[,onion]');
  return {
    fingerprint: match[1],
    password: match[2] || '',
    host: match[3],
    onionHost: match[4] || ''
  };
}

function safeEndpoint(raw, transport) {
  var parsed;
  try {
    parsed = new URL(String(raw || ''));
  } catch (_error) {
    fail('XFTP_SERVER_PROFILE_URL', 'browser XFTP endpoint URL is invalid');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'wss:') {
    fail('XFTP_SERVER_PROFILE_URL', 'browser XFTP endpoint must be https:// or wss://');
  }
  if (transport === 'websocket' && parsed.protocol !== 'wss:') {
    fail('XFTP_SERVER_PROFILE_URL', 'websocket XFTP profile requires wss://');
  }
  if (transport !== 'websocket' && parsed.protocol !== 'https:') {
    fail('XFTP_SERVER_PROFILE_URL', 'HTTPS/WebTransport XFTP profile requires https://');
  }
  parsed.username = '';
  parsed.password = '';
  parsed.hash = '';
  return parsed;
}

function safeOrigin(raw) {
  var parsed;
  try {
    parsed = new URL(String(raw || ''));
  } catch (_error) {
    fail('XFTP_SERVER_PROFILE_ORIGIN', 'allowed origin is invalid');
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
    fail('XFTP_SERVER_PROFILE_ORIGIN', 'allowed origin must be https except local development');
  }
  return parsed.origin;
}

export function normalizeBrowserXftpServerProfile(profile = {}) {
  var p = profile && typeof profile === 'object' ? profile : {};
  if (Number(p.version) !== SIMPLEX_BROWSER_XFTP_PROFILE_VERSION) {
    fail('XFTP_SERVER_PROFILE_VERSION', 'browser XFTP profile version is unsupported');
  }
  var transport = String(p.transport || '').toLowerCase();
  if (!SIMPLEX_BROWSER_XFTP_TRANSPORTS.includes(transport)) {
    fail('XFTP_SERVER_PROFILE_TRANSPORT', 'browser XFTP transport is unsupported');
  }
  var keyHash = p.keyHash instanceof Uint8Array ? toBytes(p.keyHash, 'XFTP server key hash') : decodeBase64Url(p.keyHash, 'XFTP server key hash');
  if (keyHash.length < 16 || keyHash.length > 64) fail('XFTP_SERVER_PROFILE_KEY', 'XFTP server key hash length is invalid');
  var endpoint = safeEndpoint(p.url, transport);
  var address = parseXftpServerAddress(p.xftpAddress || 'xftp://' + encodeBase64Url(keyHash) + '@' + endpoint.hostname);
  return {
    version: SIMPLEX_BROWSER_XFTP_PROFILE_VERSION,
    transport,
    url: endpoint.href,
    allowedOrigins: (Array.isArray(p.allowedOrigins) ? p.allowedOrigins : []).map(safeOrigin),
    keyHash,
    keyHashBase64Url: encodeBase64Url(keyHash),
    xftpAddress: address,
    encryptedChunksOnly: p.encryptedChunksOnly !== false,
    chunkPadding: String(p.chunkPadding || 'manifest-declared'),
    retentionHours: Math.max(1, Math.floor(Number(p.retentionHours || 48) || 48))
  };
}

export function assertProductionBrowserXftpServerProfile(profile = {}) {
  var normalized = normalizeBrowserXftpServerProfile(profile);
  if (!normalized.allowedOrigins.length) fail('XFTP_SERVER_PROFILE_ORIGIN', 'browser XFTP profile must list allowed origins');
  if (!normalized.encryptedChunksOnly) fail('XFTP_SERVER_PROFILE_ENCRYPTION', 'browser XFTP profile must require encrypted chunks only');
  if (normalized.chunkPadding !== 'manifest-declared') fail('XFTP_SERVER_PROFILE_PADDING', 'browser XFTP profile padding is unsupported');
  if (normalized.retentionHours > 168) fail('XFTP_SERVER_PROFILE_RETENTION', 'browser XFTP retention is too long');
  return normalized;
}

export default {
  BrowserXftpServerProfileError,
  SIMPLEX_BROWSER_XFTP_PROFILE_VERSION,
  assertProductionBrowserXftpServerProfile,
  normalizeBrowserXftpServerProfile,
  parseXftpServerAddress
};
