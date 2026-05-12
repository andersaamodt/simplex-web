#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
//
// Local-only helper for browser file sends/receives. Browsers cannot hand a web
// page an absolute local file path, but SimpleX file commands need one. This
// bridge stages selected browser Files under a user-state directory and serves
// only files inside explicit allowlisted roots.

import { createReadStream } from 'node:fs';
import { createServer } from 'node:http';
import { mkdir, realpath, stat, writeFile } from 'node:fs/promises';
import { basename, delimiter, extname, isAbsolute, join, relative, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';

const host = process.env.SIMPLEX_WEB_FILE_BRIDGE_HOST || '127.0.0.1';
const port = boundedInteger(process.env.SIMPLEX_WEB_FILE_BRIDGE_PORT, 5226, 0, 65535);
const maxBytes = boundedInteger(process.env.SIMPLEX_WEB_FILE_BRIDGE_MAX_BYTES, 25 * 1024 * 1024, 1, 1024 * 1024 * 1024);
const stateHome = process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state');
const storageRoot = process.env.SIMPLEX_WEB_FILE_BRIDGE_ROOT || join(stateHome, 'simplex-web', 'file-bridge');
const allowedOrigins = parseAllowedOrigins(process.env.SIMPLEX_WEB_FILE_BRIDGE_ORIGIN || 'http://127.0.0.1');
const defaultReadRoots = [
  storageRoot,
  join(stateHome, 'simplex-web', 'files'),
  join(stateHome, 'simplex-web', 'tmp')
];
const allowedReadRoots = (process.env.SIMPLEX_WEB_FILE_BRIDGE_ALLOWED_ROOTS || defaultReadRoots.join(delimiter))
  .split(delimiter)
  .map((item) => item.trim())
  .filter(Boolean)
  .map((item) => resolve(item));

function boundedInteger(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  const integer = Math.floor(parsed);
  if (integer < min || integer > max) return fallback;
  return integer;
}

function safeHeaderValue(value) {
  const raw = String(value || '').trim();
  return raw && !/[\r\n]/.test(raw) ? raw : '';
}

function safeLogValue(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/\r/g, '\\r').replace(/\n/g, '\\n');
}

function parseAllowedOrigins(value) {
  const origins = String(value || '')
    .split(',')
    .map((item) => safeHeaderValue(item))
    .filter(Boolean);
  return origins.length ? origins : ['http://127.0.0.1'];
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(String(value || ''));
  } catch (_err) {
    return String(value || '');
  }
}

function safeName(value) {
  const decoded = safeDecodeURIComponent(value || 'attachment.bin');
  const name = basename(decoded).replace(/[^\w .@+-]/g, '-').replace(/^-+/, '').slice(0, 180);
  return name || 'attachment.bin';
}

async function realPathOrResolved(filePath) {
  try {
    return await realpath(filePath);
  } catch (_err) {
    return resolve(filePath);
  }
}

async function allowedReadPath(filePath) {
  // Reads are allowed only after resolving symlinks and proving the final path
  // stays inside one configured root. Relative names are treated as basenames.
  const raw = String(filePath || '').trim();
  if (!raw) return '';
  if (!isAbsolute(raw)) {
    const fileName = safeName(raw);
    for (const root of allowedReadRoots) {
      const candidate = join(root, fileName);
      const resolvedCandidate = await realPathOrResolved(candidate);
      const resolvedRoot = await realPathOrResolved(root);
      const rel = relative(resolvedRoot, resolvedCandidate);
      if (rel === '' || (!!rel && !rel.startsWith('..') && !rel.startsWith('/') && !rel.startsWith('\\'))) {
        try {
          const info = await stat(resolvedCandidate);
          if (info.isFile()) return resolvedCandidate;
        } catch (_err) {
          // Try the next allowed root; relative file names may belong to any configured SimpleX file root.
        }
      }
    }
    return '';
  }
  const resolved = await realPathOrResolved(raw);
  for (const root of allowedReadRoots) {
    const resolvedRoot = await realPathOrResolved(root);
    const rel = relative(resolvedRoot, resolved);
    if (rel === '' || (!!rel && !rel.startsWith('..') && !rel.startsWith('/') && !rel.startsWith('\\'))) {
      return resolved;
    }
  }
  return '';
}

function noStoreHeaders(req) {
  return {
    ...corsHeaders(req),
    'X-Content-Type-Options': 'nosniff'
  };
}

function mimeForName(filePath) {
  switch (extname(filePath).toLowerCase()) {
    case '.apng':
      return 'image/apng';
    case '.avif':
      return 'image/avif';
    case '.gif':
      return 'image/gif';
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    case '.m4a':
      return 'audio/mp4';
    case '.mp3':
      return 'audio/mpeg';
    case '.mp4':
    case '.m4v':
      return 'video/mp4';
    case '.ogg':
      return 'audio/ogg';
    case '.png':
      return 'image/png';
    case '.txt':
      return 'text/plain; charset=utf-8';
    case '.wav':
      return 'audio/wav';
    case '.webm':
      return 'video/webm';
    case '.webp':
      return 'image/webp';
    default:
      return 'application/octet-stream';
  }
}

function requestOrigin(req) {
  return safeHeaderValue(req.headers.origin || '');
}

function isOriginAllowed(req) {
  const origin = requestOrigin(req);
  if (!origin) return true;
  return allowedOrigins.includes('*') || allowedOrigins.includes(origin);
}

function corsHeaders(req) {
  // The bridge is meant for a specific local page. Wildcard CORS exists only
  // for throwaway testing and is documented as unsafe for normal use.
  const origin = requestOrigin(req);
  const allowOrigin = allowedOrigins.includes('*') ? '*' : (origin && allowedOrigins.includes(origin) ? origin : allowedOrigins[0]);
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-File-Name',
    'Access-Control-Max-Age': '600',
    'Cache-Control': 'no-store'
  };
}

function sendJson(req, res, status, payload) {
  res.writeHead(status, {
    ...noStoreHeaders(req),
    'Content-Type': 'application/json; charset=utf-8'
  });
  res.end(`${JSON.stringify(payload)}\n`);
}

async function readLimitedBody(req) {
  // Stream the body with a hard byte cap so oversized uploads fail before a
  // large staging file is written to disk.
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      throw Object.assign(new Error('file too large'), { statusCode: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

const server = createServer(async (req, res) => {
  // The API surface is intentionally tiny:
  // GET /health, GET /files?path=..., and POST /files.
  try {
    if (!isOriginAllowed(req)) {
      sendJson(req, res, 403, { ok: false, error: 'origin is not allowed' });
      return;
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders(req));
      res.end();
      return;
    }
    const requestUrl = new URL(req.url || '/', `http://${host}:${port}`);
    if (req.method === 'GET' && requestUrl.pathname === '/health') {
      sendJson(req, res, 200, { ok: true, storageRoot, maxBytes });
      return;
    }
    if (req.method === 'GET' && requestUrl.pathname === '/files') {
      const filePath = requestUrl.searchParams.get('path') || '';
      const safeFilePath = filePath ? await allowedReadPath(filePath) : '';
      if (!safeFilePath) {
        sendJson(req, res, 403, { ok: false, error: 'file path is not allowed' });
        return;
      }
      const info = await stat(safeFilePath);
      if (!info.isFile()) {
        sendJson(req, res, 404, { ok: false, error: 'file not found' });
        return;
      }
      res.writeHead(200, {
        ...noStoreHeaders(req),
        'Content-Type': mimeForName(safeFilePath),
        'Content-Length': String(info.size),
        'Content-Disposition': `inline; filename="${safeName(basename(safeFilePath)).replace(/"/g, '')}"`
      });
      createReadStream(safeFilePath).pipe(res);
      return;
    }
    if (req.method !== 'POST' || requestUrl.pathname !== '/files') {
      sendJson(req, res, 404, { ok: false, error: 'not found' });
      return;
    }
    const fileName = safeName(req.headers['x-file-name']);
    const body = await readLimitedBody(req);
    const dir = join(storageRoot, `${Date.now()}-${randomBytes(8).toString('hex')}`);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const filePath = join(dir, fileName);
    await writeFile(filePath, body, { mode: 0o600 });
    sendJson(req, res, 200, {
      ok: true,
      filePath,
      name: fileName,
      size: body.length,
      mime: String(req.headers['content-type'] || 'application/octet-stream')
    });
  } catch (err) {
    sendJson(req, res, err.statusCode || 500, {
      ok: false,
      error: err && err.message ? err.message : 'file bridge error'
    });
  }
});

server.listen(port, host, () => {
  const address = server.address();
  const actualPort = address && typeof address === 'object' ? address.port : port;
  process.stdout.write(`simplex-web file bridge listening on http://${host}:${actualPort}\n`);
  process.stdout.write(`staging files under ${safeLogValue(storageRoot)}\n`);
  process.stdout.write(`serving files under ${allowedReadRoots.map(safeLogValue).join(', ')}\n`);
});
