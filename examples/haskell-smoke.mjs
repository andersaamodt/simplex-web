import { WASI, OpenFile, ConsoleStdout, PreopenDirectory } from '../node_modules/@bjorn3/browser_wasi_shim/dist/index.js';

const statusNode = document.getElementById('status');

function setStatus(message) {
  if (statusNode) {
    statusNode.textContent = message;
  }
}

async function main() {
  const wasi = new WASI([], [], [
    new OpenFile(new File([], '/dev/stdin')),
    ConsoleStdout.lineBuffered(line => console.log('[wasm stdout]', line)),
    ConsoleStdout.lineBuffered(line => console.warn('[wasm stderr]', line)),
    new PreopenDirectory('/', [])
  ]);

  const response = await fetch('../build/haskell-smoke/smoke.wasm');
  if (!response.ok) {
    throw new Error(`failed to load wasm: ${response.status}`);
  }

  const bytes = await response.arrayBuffer();
  const moduleObject = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(moduleObject, {
    wasi_snapshot_preview1: wasi.wasiImport
  });

  wasi.initialize(instance);
  if (typeof instance.exports.hs_init === 'function') {
    instance.exports.hs_init(0, 0);
  }

  const sum = instance.exports.smoke_add(9, 4);
  const fib = instance.exports.smoke_fib(10);
  setStatus(`Haskell wasm ready. smoke_add(9, 4) = ${sum}; smoke_fib(10) = ${fib}.`);
}

main().catch(error => {
  console.error(error);
  setStatus(`Haskell wasm smoke failed: ${error && error.message ? error.message : String(error)}`);
});
