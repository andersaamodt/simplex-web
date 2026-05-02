const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { WASI } = require('node:wasi');

const wasmPath = process.env.SIMPLEX_WEB_WASM_PATH || process.argv[2];

if (!wasmPath) {
  throw new Error('expected wasm path argument');
}

test('smoke wasm artifact exists', () => {
  assert.ok(fs.existsSync(wasmPath), `missing wasm artifact: ${wasmPath}`);
  assert.ok(fs.statSync(wasmPath).size > 0, 'wasm artifact is empty');
});

test('smoke reactor exports synchronous functions', async () => {
  const wasi = new WASI({ version: 'preview1' });
  const bytes = fs.readFileSync(wasmPath);
  const moduleObject = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(moduleObject, {
    wasi_snapshot_preview1: wasi.wasiImport
  });

  wasi.initialize(instance);
  if (typeof instance.exports.hs_init === 'function') {
    instance.exports.hs_init(0, 0);
  }

  assert.equal(typeof instance.exports.hs_init, 'function');
  assert.equal(typeof instance.exports.smoke_add, 'function');
  assert.equal(typeof instance.exports.smoke_fib, 'function');
  assert.equal(instance.exports.smoke_add(7, 5), 12);
  assert.equal(instance.exports.smoke_fib(10), 55);
});
