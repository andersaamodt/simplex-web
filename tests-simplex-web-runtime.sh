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

node --check "$ROOT_DIR/src/default-chat.js" >/dev/null 2>&1 || fail 'default chat source parses in Node'
node --check "$ROOT_DIR/src/session-store.js" >/dev/null 2>&1 || fail 'session store source parses in Node'
node --check "$ROOT_DIR/src/transport.js" >/dev/null 2>&1 || fail 'transport source parses in Node'
node --check "$ROOT_DIR/src/simplex-chat-websocket-adapter.js" >/dev/null 2>&1 || fail 'websocket adapter source parses in Node'
node --test "$ROOT_DIR/tests/default-chat.test.js" >/dev/null 2>&1 || fail 'default chat unit tests pass'
node --test "$ROOT_DIR/tests/session-store.test.js" >/dev/null 2>&1 || fail 'session store unit tests pass'
node --test "$ROOT_DIR/tests/transport.test.js" >/dev/null 2>&1 || fail 'transport unit tests pass'
node --test "$ROOT_DIR/tests/simplex-chat-websocket-adapter.test.js" >/dev/null 2>&1 || fail 'websocket adapter unit tests pass'

assert_file_contains "$ROOT_DIR/src/default-chat.js" 'data-secure-chat-action="login"' 'default chat exposes login action'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'Attach files' 'default chat exposes attachment control'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'shortcutModifierLabel' 'default chat exposes OS-specific send hint'
assert_file_not_contains "$ROOT_DIR/src/default-chat.js" 'Cmd/Ctrl+Enter to send' 'default chat no longer exposes generic Cmd/Ctrl send hint'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'MAX_RENDER_MESSAGES = 200' 'default chat caps rendered message history'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'function clampProgress' 'default chat clamps hostile progress values'
assert_file_contains "$ROOT_DIR/src/default-chat.js" 'function normalizeService' 'default chat normalizes transport banner strings'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'simplex-web-session-v1' 'session store uses stable storage prefix'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'slice(-MAX_MESSAGES).map(normalizeMessage)' 'session store slices before normalizing message history'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'function clampProgress' 'session store clamps hostile progress values'
assert_file_contains "$ROOT_DIR/src/session-store.js" 'MAX_STORED_JSON_LENGTH = 2097152' 'session store bounds oversized stored blobs'
assert_file_contains "$ROOT_DIR/src/default-chat.js" "secure-chat-attachment-'" 'default chat renders typed attachments inline'
assert_file_contains "$ROOT_DIR/src/default-chat.js" '<video class="secure-chat-attachment-media"' 'default chat renders video attachments inline'
assert_file_contains "$ROOT_DIR/src/transport.js" 'SIMPLEX_WEB_TRANSPORT_UNAVAILABLE' 'transport fails closed with stable error code'
assert_file_contains "$ROOT_DIR/src/transport.js" 'registerBrowserTransport' 'transport exposes browser-native adapter registration'
assert_file_contains "$ROOT_DIR/src/simplex-chat-websocket-adapter.js" 'registerSimplexChatWebSocketTransport' 'websocket adapter registers with transport facade'
assert_file_contains "$ROOT_DIR/src/simplex-chat-websocket-adapter.js" '/_send @' 'websocket adapter sends through SimpleX Chat command API'
assert_file_contains "$ROOT_DIR/docs/HASKELL_BROWSER_STATUS.md" 'no `ghc`' 'repo documents missing Haskell browser toolchain'

if [ "$FAIL_COUNT" -gt 0 ]; then
  printf 'FAIL: %s tests failed; %s passed\n' "$FAIL_COUNT" "$PASS_COUNT" >&2
  exit 1
fi

printf 'ok (%s assertions)\n' "$PASS_COUNT"
