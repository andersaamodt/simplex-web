#!/bin/sh

set -eu

cd "$(dirname "$0")"

assert_file_exists() {
  if [ ! -f "$1" ]; then
    printf 'ASSERTION FAILED: expected file %s\n' "$1" >&2
    exit 1
  fi
}

assert_nonempty_file() {
  if [ ! -s "$1" ]; then
    printf 'ASSERTION FAILED: expected nonempty file %s\n' "$1" >&2
    exit 1
  fi
}

if ! command -v wasm32-wasi-ghc >/dev/null 2>&1; then
  printf 'wasm32-wasi-ghc is required; source ~/.ghc-wasm/env first\n' >&2
  exit 1
fi

build_dir="build/haskell-core"
mkdir -p "$build_dir"

wasm_path="$build_dir/core.wasm"
js_path="$build_dir/core.mjs"
libdir="$(wasm32-wasi-ghc --print-libdir)"

wasm32-wasi-ghc \
  -fforce-recomp \
  -O0 \
  -i./haskell/src \
  -no-hs-main \
  -optl-mexec-model=reactor \
  -optl-Wl,--export=hs_init \
  -optl-Wl,--export=core_reset \
  -optl-Wl,--export=core_login \
  -optl-Wl,--export=core_logout \
  -optl-Wl,--export=core_set_draft \
  -optl-Wl,--export=core_set_error \
  -optl-Wl,--export=core_clear_error \
  -optl-Wl,--export=core_send_text \
  -optl-Wl,--export=core_receive_text \
  -optl-Wl,--export=core_set_delivery_status \
  -optl-Wl,--export=core_add_upload \
  -optl-Wl,--export=core_update_upload \
  -optl-Wl,--export=core_snapshot_json \
  -optl-Wl,--export=core_message_count \
  -optl-Wl,--export=core_is_jsffi_used \
  ./haskell/src/Simplex/Web/Core.hs \
  -o "$wasm_path"

"$libdir/post-link.mjs" -i "$wasm_path" -o "$js_path"

assert_file_exists "$wasm_path"
assert_nonempty_file "$wasm_path"
assert_file_exists "$js_path"
assert_nonempty_file "$js_path"

SIMPLEX_WEB_CORE_WASM_PATH="$wasm_path" SIMPLEX_WEB_CORE_JS_PATH="$js_path" node --test ./tests/haskell-core.test.mjs

printf 'ok\n'
