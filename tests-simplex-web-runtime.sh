#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf 'FAIL: %s\n' "$1" >&2
}

assert_file_contains() {
  file=$1
  needle=$2
  label=$3
  if grep -Fq "$needle" "$file"; then
    pass
  else
    fail "$label (missing: $needle in $file)"
  fi
}

assert_file_not_contains() {
  file=$1
  needle=$2
  label=$3
  if grep -Fq "$needle" "$file"; then
    fail "$label (unexpected: $needle in $file)"
  else
    pass
  fi
}

assert_file_missing() {
  file=$1
  label=$2
  if [ -e "$file" ]; then
    fail "$label (unexpected file exists: $file)"
  else
    pass
  fi
}

node --check "$ROOT_DIR/src/default-chat.js" >/dev/null 2>&1 || fail 'default chat source parses in Node'
node --check "$ROOT_DIR/src/session-store.js" >/dev/null 2>&1 || fail 'session store source parses in Node'
node --check "$ROOT_DIR/src/transport.js" >/dev/null 2>&1 || fail 'transport source parses in Node'
node --check "$ROOT_DIR/src/browser-smp-core.mjs" >/dev/null 2>&1 || fail 'browser SMP core source parses in Node'
node --check "$ROOT_DIR/src/browser-simplex-agent.mjs" >/dev/null 2>&1 || fail 'browser SimpleX agent source parses in Node'
node --check "$ROOT_DIR/src/browser-simplex-client.mjs" >/dev/null 2>&1 || fail 'browser SimpleX client source parses in Node'
node --check "$ROOT_DIR/src/browser-simplex-contact-client.mjs" >/dev/null 2>&1 || fail 'browser SimpleX contact client source parses in Node'
node --check "$ROOT_DIR/src/browser-simplex-ratchet.mjs" >/dev/null 2>&1 || fail 'browser SimpleX ratchet source parses in Node'
node --check "$ROOT_DIR/src/browser-simplex-scheduler.mjs" >/dev/null 2>&1 || fail 'browser SimpleX scheduler source parses in Node'
node --check "$ROOT_DIR/src/browser-simplex-store.mjs" >/dev/null 2>&1 || fail 'browser SimpleX store source parses in Node'
node --check "$ROOT_DIR/src/browser-smp-server-profile.mjs" >/dev/null 2>&1 || fail 'browser SMP server profile source parses in Node'
node --check "$ROOT_DIR/src/browser-smp-websocket-transport.mjs" >/dev/null 2>&1 || fail 'browser SMP websocket transport source parses in Node'
node --check "$ROOT_DIR/src/browser-xftp-core.mjs" >/dev/null 2>&1 || fail 'browser XFTP core source parses in Node'
node --test "$ROOT_DIR/tests/default-chat.test.js" >/dev/null 2>&1 || fail 'default chat unit tests pass'
node --test "$ROOT_DIR/tests/session-store.test.js" >/dev/null 2>&1 || fail 'session store unit tests pass'
node --test "$ROOT_DIR/tests/transport.test.js" >/dev/null 2>&1 || fail 'transport unit tests pass'
node --test "$ROOT_DIR/tests/browser-smp-core.test.mjs" >/dev/null 2>&1 || fail 'browser SMP core unit tests pass'
node --test "$ROOT_DIR/tests/browser-simplex-agent.test.mjs" >/dev/null 2>&1 || fail 'browser SimpleX agent unit tests pass'
node --test "$ROOT_DIR/tests/browser-simplex-client.test.mjs" >/dev/null 2>&1 || fail 'browser SimpleX client unit tests pass'
node --test "$ROOT_DIR/tests/browser-simplex-contact-client.test.mjs" >/dev/null 2>&1 || fail 'browser SimpleX contact client unit tests pass'
node --test "$ROOT_DIR/tests/browser-simplex-ratchet.test.mjs" >/dev/null 2>&1 || fail 'browser SimpleX ratchet unit tests pass'
node --test "$ROOT_DIR/tests/browser-simplex-scheduler.test.mjs" >/dev/null 2>&1 || fail 'browser SimpleX scheduler unit tests pass'
node --test "$ROOT_DIR/tests/browser-simplex-store.test.mjs" >/dev/null 2>&1 || fail 'browser SimpleX store unit tests pass'
node --test "$ROOT_DIR/tests/browser-smp-server-profile.test.mjs" >/dev/null 2>&1 || fail 'browser SMP server profile unit tests pass'
node --test "$ROOT_DIR/tests/browser-smp-websocket-transport.test.mjs" >/dev/null 2>&1 || fail 'browser SMP websocket transport unit tests pass'
node --test "$ROOT_DIR/tests/browser-xftp-core.test.mjs" >/dev/null 2>&1 || fail 'browser XFTP core unit tests pass'

assert_file_contains "$ROOT_DIR/src/default-chat.js" 'data-secure-chat-action="login"' 'default chat exposes login action'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'Attach files' 'default chat exposes attachment control'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'shortcutModifierLabel' 'default chat exposes OS-specific send hint'
assert_file_not_contains "$ROOT_DIR/src/default-chat.js" 'Cmd/Ctrl+Enter to send' 'default chat no longer exposes generic Cmd/Ctrl send hint'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'MAX_RENDER_MESSAGES = 200' 'default chat caps rendered message history'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'function clampProgress' 'default chat clamps hostile progress values'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'function normalizeService' 'default chat normalizes transport banner strings'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'function containsActionNode' 'default chat validates delegated action root membership'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'simplex-web-session-v1' 'session store uses stable storage prefix'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'slice(-MAX_MESSAGES).map(normalizeMessage)' 'session store slices before normalizing message history'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'function clampProgress' 'session store clamps hostile progress values'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'MAX_STORED_JSON_LENGTH = 2097152' 'session store bounds oversized stored blobs'
assert_file_contains "$ROOT_DIR/src/default-chat.js" "secure-chat-attachment-'" 'default chat renders typed attachments inline'
assert_file_contains "$ROOT_DIR/src/default-chat.js" '<video class="secure-chat-attachment-media"' 'default chat renders video attachments inline'
assert_file_contains "$ROOT_DIR/src/transport.js" 'SIMPLEX_WEB_TRANSPORT_UNAVAILABLE' 'transport fails closed with stable error code'
assert_file_contains "$ROOT_DIR/src/transport.js" 'registerBrowserTransport' 'transport exposes browser-native adapter registration'
assert_file_contains "$ROOT_DIR/src/browser-smp-core.mjs" 'encodeTransportBlock' 'browser SMP core encodes fixed-size transport blocks'
assert_file_contains "$ROOT_DIR/src/browser-simplex-agent.mjs" 'prepareNewQueueRequest' 'browser SimpleX agent prepares NEW queue requests'
assert_file_contains "$ROOT_DIR/src/browser-simplex-client.mjs" 'createQueue' 'browser SimpleX client orchestrates queue creation'
assert_file_contains "$ROOT_DIR/src/browser-simplex-contact-client.mjs" 'CONTACT_STATE_ACTIVE' 'browser SimpleX contact client owns active contact state'
assert_file_contains "$ROOT_DIR/src/browser-simplex-contact-client.mjs" 'receiveNext' 'browser SimpleX contact client receives and acknowledges queue messages'
assert_file_contains "$ROOT_DIR/src/browser-simplex-contact-client.mjs" 'drainDueRetries' 'browser SimpleX contact client drains retry tasks'
assert_file_contains "$ROOT_DIR/src/browser-simplex-ratchet.mjs" 'decryptRatchetMessage' 'browser SimpleX ratchet decrypts message packets'
assert_file_contains "$ROOT_DIR/src/browser-simplex-scheduler.mjs" 'nextRetryDelay' 'browser SimpleX scheduler computes bounded backoff'
assert_file_contains "$ROOT_DIR/src/browser-simplex-store.mjs" 'saveContact' 'browser SimpleX store persists contacts'
assert_file_contains "$ROOT_DIR/src/browser-smp-server-profile.mjs" 'assertProductionBrowserSmpServerProfile' 'browser SMP server profile fails closed'
assert_file_contains "$ROOT_DIR/src/browser-smp-websocket-transport.mjs" 'binarySmpBlocksOnly' 'browser SMP websocket transport rejects non-binary frames'
assert_file_contains "$ROOT_DIR/src/browser-xftp-core.mjs" 'assembleXftpDownload' 'browser XFTP core verifies downloads'
assert_file_missing "$ROOT_DIR/src/simplex-chat-websocket-adapter.js" 'daemon-backed websocket adapter is not shipped'
assert_file_missing "$ROOT_DIR/scripts/simplex-web-file-bridge.mjs" 'loopback file bridge is not shipped'
assert_file_missing "$ROOT_DIR/examples/mock-chat.html" 'mock chat example is not shipped'
assert_file_not_contains "$ROOT_DIR/package.json" 'simplex-chat-websocket-adapter' 'package exports do not expose daemon-backed adapter'
assert_file_not_contains "$ROOT_DIR/package.json" 'file-bridge' 'package scripts do not expose loopback file bridge'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'safeAttachmentUrl' 'default chat sanitizes rendered attachment URLs'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'isLoopbackHost(parsed.hostname)' 'default chat only autoloads loopback attachment URLs'
assert_file_contains "$ROOT_DIR/src/transport.js" 'transport.registerBrowserTransport = registerBrowserTransport' 'registered transport remains replaceable'
assert_file_contains "$ROOT_DIR/docs/HASKELL_BROWSER_STATUS.md" 'official `ghc-wasm-meta` toolchain' 'repo documents completed Haskell browser toolchain validation'
assert_file_contains "$ROOT_DIR/docs/HASKELL_BROWSER_STATUS.md" '`npm run test:haskell` passes' 'repo documents passing Haskell browser checks'

if [ "$FAIL_COUNT" -gt 0 ]; then
  printf 'FAIL: %s tests failed; %s passed\n' "$FAIL_COUNT" "$PASS_COUNT" >&2
  exit 1
fi

printf 'ok (%s assertions)\n' "$PASS_COUNT"
