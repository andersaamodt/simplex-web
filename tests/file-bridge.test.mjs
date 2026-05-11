import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

async function requestJson(url, options = {}) {
  const resp = await fetch(url, options);
  const text = await resp.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (_err) {
    json = null;
  }
  return { resp, text, json };
}

function startBridge(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/simplex-web-file-bridge.mjs'], {
      cwd: process.cwd(),
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`file bridge did not start\nstdout=${stdout}\nstderr=${stderr}`));
    }, 5000);
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      const match = stdout.match(/http:\/\/127\.0\.0\.1:(\d+)/);
      if (match) {
        clearTimeout(timer);
        resolve({
          child,
          baseUrl: `http://127.0.0.1:${match[1]}`,
          async stop() {
            child.kill();
            await new Promise((done) => child.once('exit', done));
          }
        });
      }
    });
    child.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      if (!stdout.match(/http:\/\/127\.0\.0\.1:(\d+)/)) {
        reject(new Error(`file bridge exited before startup with ${code}\nstdout=${stdout}\nstderr=${stderr}`));
      }
    });
  });
}

test('file bridge rejects hostile origins, traversal reads, and malformed filenames', async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), 'simplex-web-file-bridge-test-'));
  const storageRoot = join(tempRoot, 'staging');
  const allowedRoot = join(tempRoot, 'allowed');
  const outsideRoot = join(tempRoot, 'outside');
  await mkdir(storageRoot, { recursive: true });
  await mkdir(allowedRoot, { recursive: true });
  await mkdir(outsideRoot, { recursive: true });
  const outsideFile = join(outsideRoot, 'secret.txt');
  await writeFile(outsideFile, 'secret');

  const bridge = await startBridge({
    SIMPLEX_WEB_FILE_BRIDGE_HOST: '127.0.0.1',
    SIMPLEX_WEB_FILE_BRIDGE_PORT: '0',
    SIMPLEX_WEB_FILE_BRIDGE_ROOT: storageRoot,
    SIMPLEX_WEB_FILE_BRIDGE_ALLOWED_ROOTS: allowedRoot,
    SIMPLEX_WEB_FILE_BRIDGE_ORIGIN: 'https://allowed.example'
  });

  try {
    const hostile = await requestJson(`${bridge.baseUrl}/health`, {
      headers: { Origin: 'https://evil.example' }
    });
    assert.equal(hostile.resp.status, 403);
    assert.notEqual(hostile.resp.headers.get('access-control-allow-origin'), 'https://evil.example');

    const blockedRead = await requestJson(`${bridge.baseUrl}/files?path=${encodeURIComponent(outsideFile)}`, {
      headers: { Origin: 'https://allowed.example' }
    });
    assert.equal(blockedRead.resp.status, 403);

    const staged = await requestJson(`${bridge.baseUrl}/files`, {
      method: 'POST',
      headers: {
        Origin: 'https://allowed.example',
        'Content-Type': 'text/plain',
        'X-File-Name': '%E0%A4%A/../../bad<script>.txt'
      },
      body: 'hello'
    });
    assert.equal(staged.resp.status, 200);
    assert.equal(staged.json.ok, true);
    assert.match(staged.json.filePath, /^\/.*bad-script-\.txt$/);
    assert.equal(await readFile(staged.json.filePath, 'utf8'), 'hello');
    assert.equal(staged.resp.headers.get('x-content-type-options'), 'nosniff');
  } finally {
    await bridge.stop();
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test('file bridge rejects symlink escapes and oversized uploads without staging files', async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), 'simplex-web-file-bridge-test-'));
  const storageRoot = join(tempRoot, 'staging');
  const allowedRoot = join(tempRoot, 'allowed');
  const outsideRoot = join(tempRoot, 'outside');
  await mkdir(storageRoot, { recursive: true });
  await mkdir(allowedRoot, { recursive: true });
  await mkdir(outsideRoot, { recursive: true });
  const outsideFile = join(outsideRoot, 'secret.txt');
  const symlinkPath = join(allowedRoot, 'secret-link.txt');
  await writeFile(outsideFile, 'secret');
  await symlink(outsideFile, symlinkPath);

  const bridge = await startBridge({
    SIMPLEX_WEB_FILE_BRIDGE_HOST: '127.0.0.1',
    SIMPLEX_WEB_FILE_BRIDGE_PORT: '0',
    SIMPLEX_WEB_FILE_BRIDGE_ROOT: storageRoot,
    SIMPLEX_WEB_FILE_BRIDGE_ALLOWED_ROOTS: allowedRoot,
    SIMPLEX_WEB_FILE_BRIDGE_MAX_BYTES: '4',
    SIMPLEX_WEB_FILE_BRIDGE_ORIGIN: 'https://allowed.example'
  });

  try {
    const symlinkRead = await requestJson(`${bridge.baseUrl}/files?path=${encodeURIComponent(symlinkPath)}`, {
      headers: { Origin: 'https://allowed.example' }
    });
    assert.equal(symlinkRead.resp.status, 403);

    const oversized = await requestJson(`${bridge.baseUrl}/files`, {
      method: 'POST',
      headers: {
        Origin: 'https://allowed.example',
        'Content-Type': 'text/plain',
        'X-File-Name': 'too-large.txt'
      },
      body: '12345'
    });
    assert.equal(oversized.resp.status, 413);
    assert.deepEqual(await readdir(storageRoot), []);
  } finally {
    await bridge.stop();
    await rm(tempRoot, { recursive: true, force: true });
  }
});
