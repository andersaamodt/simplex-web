// SPDX-License-Identifier: AGPL-3.0-only
//
// Browser SMP server profile validation.
//
// Browser JavaScript cannot reproduce native raw TCP/TLS SMP security checks.
// A production browser endpoint therefore has to advertise an explicit browser
// profile: binary frames, fixed SMP block size, server identity hash, allowed
// origin, and a reviewed session-binding replacement.

import {
  SMP_BLOCK_SIZE,
  decodeBase64Url,
  encodeBase64Url,
  toBytes
} from './browser-smp-core.mjs';

export const SIMPLEX_BROWSER_SMP_PROFILE_VERSION = 1;
export const SIMPLEX_BROWSER_SMP_TRANSPORTS = Object.freeze(['websocket', 'webtransport']);

export class BrowserSmpServerProfileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BrowserSmpServerProfileError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new BrowserSmpServerProfileError(code, message);
}

function safeUrl(raw) {
  var parsed;
  try {
    parsed = new URL(String(raw || ''));
  } catch (_error) {
    fail('SIMPLEX_SERVER_PROFILE_URL', 'server profile URL is invalid');
  }
  if (parsed.protocol !== 'wss:' && parsed.protocol !== 'https:') {
    fail('SIMPLEX_SERVER_PROFILE_URL', 'production browser SMP profile requires wss:// or https://');
  }
  parsed.hash = '';
  parsed.username = '';
  parsed.password = '';
  return parsed.href;
}

function safeOrigin(raw) {
  var parsed;
  try {
    parsed = new URL(String(raw || ''));
  } catch (_error) {
    fail('SIMPLEX_SERVER_PROFILE_ORIGIN', 'allowed origin is invalid');
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
    fail('SIMPLEX_SERVER_PROFILE_ORIGIN', 'allowed origin must be https except local development');
  }
  return parsed.origin;
}

export function normalizeBrowserSmpServerProfile(profile = {}) {
  var p = profile && typeof profile === 'object' ? profile : {};
  if (Number(p.version) !== SIMPLEX_BROWSER_SMP_PROFILE_VERSION) {
    fail('SIMPLEX_SERVER_PROFILE_VERSION', 'browser SMP server profile version is unsupported');
  }
  var transport = String(p.transport || '').toLowerCase();
  if (!SIMPLEX_BROWSER_SMP_TRANSPORTS.includes(transport)) {
    fail('SIMPLEX_SERVER_PROFILE_TRANSPORT', 'browser SMP server profile transport is unsupported');
  }
  var keyHash = p.keyHash instanceof Uint8Array ? toBytes(p.keyHash, 'server key hash') : decodeBase64Url(p.keyHash, 'server key hash');
  if (keyHash.length < 16 || keyHash.length > 64) fail('SIMPLEX_SERVER_PROFILE_KEY', 'server key hash length is invalid');
  var binding = p.sessionBinding && typeof p.sessionBinding === 'object' ? p.sessionBinding : {};
  if (binding.type !== 'exported-authenticator' && binding.type !== 'signed-handshake') {
    fail('SIMPLEX_SERVER_PROFILE_BINDING', 'server profile must define a reviewed session binding replacement');
  }
  return {
    version: SIMPLEX_BROWSER_SMP_PROFILE_VERSION,
    transport,
    url: safeUrl(p.url),
    allowedOrigins: (Array.isArray(p.allowedOrigins) ? p.allowedOrigins : []).map(safeOrigin),
    keyHash,
    keyHashBase64Url: encodeBase64Url(keyHash),
    blockSize: Number(p.blockSize || SMP_BLOCK_SIZE),
    binaryFramesOnly: p.binaryFramesOnly !== false,
    padding: String(p.padding || 'smp-16384'),
    sessionBinding: {
      type: binding.type,
      context: String(binding.context || 'simplex-web browser smp').slice(0, 160)
    }
  };
}

export function assertProductionBrowserSmpServerProfile(profile = {}) {
  var normalized = normalizeBrowserSmpServerProfile(profile);
  if (!normalized.allowedOrigins.length) fail('SIMPLEX_SERVER_PROFILE_ORIGIN', 'server profile must list allowed origins');
  if (normalized.blockSize !== SMP_BLOCK_SIZE) fail('SIMPLEX_SERVER_PROFILE_BLOCK', 'server profile must use 16384-byte SMP blocks');
  if (!normalized.binaryFramesOnly) fail('SIMPLEX_SERVER_PROFILE_BINARY', 'server profile must require binary frames');
  if (normalized.padding !== 'smp-16384') fail('SIMPLEX_SERVER_PROFILE_PADDING', 'server profile padding is unsupported');
  return normalized;
}

export default {
  BrowserSmpServerProfileError,
  SIMPLEX_BROWSER_SMP_PROFILE_VERSION,
  assertProductionBrowserSmpServerProfile,
  normalizeBrowserSmpServerProfile
};
