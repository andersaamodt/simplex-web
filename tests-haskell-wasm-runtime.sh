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

build_dir="build/haskell-smoke"
mkdir -p "$build_dir"

wasm_path="$build_dir/smoke.wasm"

wasm32-wasi-ghc \
  -fforce-recomp \
  -O0 \
  -i./haskell/src \
  -no-hs-main \
  -optl-mexec-model=reactor \
  -optl-Wl,--export=hs_init \
  -optl-Wl,--export=smoke_add \
  -optl-Wl,--export=smoke_fib \
  ./haskell/src/Simplex/Web/Smoke.hs \
  -o "$wasm_path"

assert_file_exists "$wasm_path"
assert_nonempty_file "$wasm_path"

SIMPLEX_WEB_WASM_PATH="$wasm_path" node --test ./tests/haskell-smoke.test.cjs

printf 'ok\n'
