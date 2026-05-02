import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { WASI, OpenFile, ConsoleStdout, PreopenDirectory } from '../node_modules/@bjorn3/browser_wasi_shim/dist/index.js';

const wasmPath = process.env.SIMPLEX_WEB_CORE_WASM_PATH;
const jsPath = process.env.SIMPLEX_WEB_CORE_JS_PATH;

if (!wasmPath || !jsPath) {
  throw new Error('expected SIMPLEX_WEB_CORE_WASM_PATH and SIMPLEX_WEB_CORE_JS_PATH');
}

async function instantiateCore() {
  const wasi = new WASI([], [], [
    new OpenFile(new File([], '/dev/stdin')),
    ConsoleStdout.lineBuffered(() => {}),
    ConsoleStdout.lineBuffered(() => {}),
    new PreopenDirectory('/', [])
  ]);
  const bytes = fs.readFileSync(wasmPath);
  const moduleObject = await WebAssembly.compile(bytes);
  const coreModule = await import(pathToFileURL(jsPath).href);
  const exportsRef = {};
  const instance = await WebAssembly.instantiate(moduleObject, {
    ghc_wasm_jsffi: coreModule.default(exportsRef),
    wasi_snapshot_preview1: wasi.wasiImport
  });
  Object.assign(exportsRef, instance.exports);
  wasi.initialize(instance);
  instance.exports.hs_init(0, 0);
  return instance.exports;
}

test('core exports are available and JSFFI is active', async () => {
  const exportsObject = await instantiateCore();
  assert.equal(typeof exportsObject.core_reset, 'function');
  assert.equal(typeof exportsObject.core_snapshot_json, 'function');
  assert.equal(typeof exportsObject.core_send_text, 'function');
  assert.equal(exportsObject.core_is_jsffi_used(), 1);
});

test('core state transitions preserve message order and upload progress', async () => {
  const exportsObject = await instantiateCore();
  exportsObject.core_reset();
  exportsObject.core_login();
  exportsObject.core_set_draft('draft one');
  assert.equal(exportsObject.core_send_text('first outgoing'), 1);
  assert.equal(exportsObject.core_receive_text('first reply'), 2);
  assert.equal(exportsObject.core_set_delivery_status(1, 'delivered'), 1);
  assert.equal(exportsObject.core_add_upload('notes.txt'), 1);
  assert.equal(exportsObject.core_update_upload(1, 75, 'uploading'), 1);
  exportsObject.core_set_error('none');
  const snapshot = JSON.parse(exportsObject.core_snapshot_json());

  assert.equal(snapshot.loggedIn, true);
  assert.equal(snapshot.draftText, '');
  assert.equal(snapshot.messages.length, 2);
  assert.equal(snapshot.messages[0].text, 'first outgoing');
  assert.equal(snapshot.messages[0].delivery_status, 'delivered');
  assert.equal(snapshot.messages[1].direction, 'incoming');
  assert.equal(snapshot.messages[1].text, 'first reply');
  assert.equal(snapshot.uploads.length, 1);
  assert.equal(snapshot.uploads[0].name, 'notes.txt');
  assert.equal(snapshot.uploads[0].progress, 75);
  assert.equal(snapshot.error, 'none');
});

test('core snapshot escapes hostile strings into valid JSON', async () => {
  const exportsObject = await instantiateCore();
  exportsObject.core_reset();
  exportsObject.core_login();
  exportsObject.core_receive_text('\"<script>alert(1)</script>');
  const snapshotText = exportsObject.core_snapshot_json();
  const parsed = JSON.parse(snapshotText);
  assert.equal(parsed.messages[0].text, '\"<script>alert(1)</script>');
});
