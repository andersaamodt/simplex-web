#!/usr/bin/env node
import { createReadStream } from 'node:fs';
import { createServer } from 'node:http';
import { mkdir, stat, writeFile } from 'node:fs/promises';
import { basename, delimiter, extname, join, relative, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';

const host = process.env.SIMPLEX_WEB_FILE_BRIDGE_HOST || '127.0.0.1';
const port = Number(process.env.SIMPLEX_WEB_FILE_BRIDGE_PORT || 5226);
const maxBytes = Number(process.env.SIMPLEX_WEB_FILE_BRIDGE_MAX_BYTES || 25 * 1024 * 1024);
const stateHome = process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state');
const storageRoot = process.env.SIMPLEX_WEB_FILE_BRIDGE_ROOT || join(stateHome, 'simplex-web', 'file-bridge');
const allowedOrigin = process.env.SIMPLEX_WEB_FILE_BRIDGE_ORIGIN || '*';
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

function safeName(value) {
  const decoded = decodeURIComponent(String(value || 'attachment.bin'));
  const name = basename(decoded).replace(/[^\w .@+-]/g, '-').replace(/^-+/, '').slice(0, 180);
  return name || 'attachment.bin';
}

function isPathAllowed(filePath) {
  const resolved = resolve(filePath);
  return allowedReadRoots.some((root) => {
    const rel = relative(root, resolved);
    return rel === '' || (!!rel && !rel.startsWith('..') && !rel.startsWith('/'));
  });
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

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-File-Name',
    'Access-Control-Max-Age': '600',
    'Cache-Control': 'no-store'
  };
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    ...corsHeaders(),
    'Content-Type': 'application/json; charset=utf-8'
  });
  res.end(`${JSON.stringify(payload)}\n`);
}

async function readLimitedBody(req) {
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
  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders());
      res.end();
      return;
    }
    const requestUrl = new URL(req.url || '/', `http://${host}:${port}`);
    if (req.method === 'GET' && requestUrl.pathname === '/health') {
      sendJson(res, 200, { ok: true, storageRoot, maxBytes });
      return;
    }
    if (req.method === 'GET' && requestUrl.pathname === '/files') {
      const filePath = requestUrl.searchParams.get('path') || '';
      if (!filePath || !isPathAllowed(filePath)) {
        sendJson(res, 403, { ok: false, error: 'file path is not allowed' });
        return;
      }
      const info = await stat(filePath);
      if (!info.isFile()) {
        sendJson(res, 404, { ok: false, error: 'file not found' });
        return;
      }
      res.writeHead(200, {
        ...corsHeaders(),
        'Content-Type': mimeForName(filePath),
        'Content-Length': String(info.size),
        'Content-Disposition': `inline; filename="${safeName(basename(filePath)).replace(/"/g, '')}"`
      });
      createReadStream(filePath).pipe(res);
      return;
    }
    if (req.method !== 'POST' || requestUrl.pathname !== '/files') {
      sendJson(res, 404, { ok: false, error: 'not found' });
      return;
    }
    const fileName = safeName(req.headers['x-file-name']);
    const body = await readLimitedBody(req);
    const dir = join(storageRoot, `${Date.now()}-${randomBytes(8).toString('hex')}`);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const filePath = join(dir, fileName);
    await writeFile(filePath, body, { mode: 0o600 });
    sendJson(res, 200, {
      ok: true,
      filePath,
      name: fileName,
      size: body.length,
      mime: String(req.headers['content-type'] || 'application/octet-stream')
    });
  } catch (err) {
    sendJson(res, err.statusCode || 500, {
      ok: false,
      error: err && err.message ? err.message : 'file bridge error'
    });
  }
});

server.listen(port, host, () => {
  process.stdout.write(`simplex-web file bridge listening on http://${host}:${port}\n`);
  process.stdout.write(`staging files under ${storageRoot}\n`);
  process.stdout.write(`serving files under ${allowedReadRoots.join(', ')}\n`);
});
