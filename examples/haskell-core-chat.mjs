import { WASI, OpenFile, ConsoleStdout, PreopenDirectory } from '../node_modules/@bjorn3/browser_wasi_shim/dist/index.js';

const statusNode = document.getElementById('demo-status');
const root = document.getElementById('chat-root');
const replyButton = document.getElementById('simulate-reply');
const deliveredButton = document.getElementById('mark-delivered');
const uploadButton = document.getElementById('queue-upload');
const resetButton = document.getElementById('reset-chat');

function setStatus(message) {
  if (statusNode) {
    statusNode.textContent = message;
  }
}

function parseSnapshot(core) {
  return JSON.parse(core.core_snapshot_json());
}

async function loadCore() {
  const wasi = new WASI([], [], [
    new OpenFile(new File([], '/dev/stdin')),
    ConsoleStdout.lineBuffered(line => console.log('[wasm stdout]', line)),
    ConsoleStdout.lineBuffered(line => console.warn('[wasm stderr]', line)),
    new PreopenDirectory('/', [])
  ]);

  const [wasmResponse, glueModule] = await Promise.all([
    fetch('../build/haskell-core/core.wasm'),
    import('../build/haskell-core/core.mjs')
  ]);

  if (!wasmResponse.ok) {
    throw new Error(`failed to load core.wasm: ${wasmResponse.status}`);
  }

  const bytes = await wasmResponse.arrayBuffer();
  const moduleObject = await WebAssembly.compile(bytes);
  const exportsRef = {};
  const instance = await WebAssembly.instantiate(moduleObject, {
    ghc_wasm_jsffi: glueModule.default(exportsRef),
    wasi_snapshot_preview1: wasi.wasiImport
  });

  Object.assign(exportsRef, instance.exports);
  wasi.initialize(instance);
  if (typeof instance.exports.hs_init === 'function') {
    instance.exports.hs_init(0, 0);
  }
  return instance.exports;
}

async function main() {
  if (!window.SimplexWebDefaultChat || typeof window.SimplexWebDefaultChat.mount !== 'function') {
    throw new Error('SimplexWebDefaultChat is not available');
  }
  if (!root) {
    throw new Error('chat root is missing');
  }

  const core = await loadCore();
  core.core_reset();

  let outgoingCount = 0;

  const widget = window.SimplexWebDefaultChat.mount(root, parseSnapshot(core), {
    onLogin() {
      core.core_login();
      render();
    },
    onSend(text) {
      const nextText = String(text || '').trim();
      if (!nextText) {
        core.core_set_error('Write a message before sending.');
        render();
        return;
      }
      core.core_clear_error();
      const sequence = core.core_send_text(nextText);
      outgoingCount += 1;
      render();
      window.setTimeout(() => {
        core.core_set_delivery_status(sequence, outgoingCount % 2 === 0 ? 'delivered' : 'sent');
        render();
      }, 250);
    },
    onDraftChange(text) {
      core.core_set_draft(String(text || ''));
    },
    onFilesSelected(files) {
      const nextFiles = Array.isArray(files) ? files : [];
      nextFiles.forEach((file, index) => {
        const uploadId = core.core_add_upload(file && file.name ? file.name : `upload-${index + 1}`);
        render();
        window.setTimeout(() => {
          core.core_update_upload(uploadId, 45, 'uploading');
          render();
        }, 150);
        window.setTimeout(() => {
          core.core_update_upload(uploadId, 100, 'complete');
          render();
        }, 450);
      });
    }
  });

  function render() {
    widget.render(parseSnapshot(core));
  }

  replyButton?.addEventListener('click', () => {
    core.core_receive_text('Simulated browser-side reply from the Haskell core.');
    render();
  });

  deliveredButton?.addEventListener('click', () => {
    core.core_set_delivery_status(1, 'delivered');
    render();
  });

  uploadButton?.addEventListener('click', () => {
    const uploadId = core.core_add_upload('demo-attachment.txt');
    render();
    window.setTimeout(() => {
      core.core_update_upload(uploadId, 30, 'uploading');
      render();
    }, 120);
    window.setTimeout(() => {
      core.core_update_upload(uploadId, 100, 'complete');
      render();
    }, 320);
  });

  resetButton?.addEventListener('click', () => {
    core.core_reset();
    render();
  });

  render();
  setStatus('Haskell core loaded. Use Login..., send messages, and simulate replies or uploads from the demo controls.');
}

main().catch(error => {
  console.error(error);
  setStatus(`Haskell core demo failed: ${error && error.message ? error.message : String(error)}`);
});
