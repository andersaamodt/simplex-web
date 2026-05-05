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

test('core bounds hostile text, statuses, and retained history', async () => {
  const exportsObject = await instantiateCore();
  exportsObject.core_reset();
  exportsObject.core_login();
  exportsObject.core_set_draft('d'.repeat(5000));
  exportsObject.core_set_error('e'.repeat(5000));
  const truncatedState = JSON.parse(exportsObject.core_snapshot_json());
  assert.equal(truncatedState.draftText.length, 4000);
  assert.equal(truncatedState.error.length, 4000);

  for (let i = 0; i < 205; i += 1) {
    exportsObject.core_send_text(`message-${i}-${'x'.repeat(5000)}`);
  }
  for (let i = 0; i < 55; i += 1) {
    exportsObject.core_add_upload(`upload-${i}-${'n'.repeat(400)}`);
  }
  assert.equal(exportsObject.core_update_upload(55, 9999, 's'.repeat(200)), 1);

  const snapshot = JSON.parse(exportsObject.core_snapshot_json());
  assert.equal(snapshot.draftText, '');
  assert.equal(snapshot.error, '');
  assert.equal(snapshot.messages.length, 200);
  assert.equal(snapshot.messages[0].sequence, 6);
  assert.equal(snapshot.messages[0].text.startsWith('message-5-'), true);
  assert.equal(snapshot.messages[0].text.length, 4000);
  assert.equal(snapshot.messages[snapshot.messages.length - 1].sequence, 205);
  assert.equal(snapshot.uploads.length, 50);
  assert.equal(snapshot.uploads[0].upload_id, 6);
  assert.equal(snapshot.uploads[0].name.length, 256);
  assert.equal(snapshot.uploads[snapshot.uploads.length - 1].progress, 100);
  assert.equal(snapshot.uploads[snapshot.uploads.length - 1].status.length, 64);
});
