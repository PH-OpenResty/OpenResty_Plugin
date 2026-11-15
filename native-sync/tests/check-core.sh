#!/bin/sh
set -eu
native_module=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
native_check=$(mktemp -d /tmp/scdn-native-core.XXXXXXXX)
trap 'rm -rf -- "$native_check"' EXIT
trap 'exit 1' HUP INT TERM
${CC:-cc} -std=c99 -Wall -Wextra -Werror -pedantic \
  ${SCDN_NATIVE_SANITIZERS:-} -I "$native_module/src" \
  "$native_module/src/scdn_sync_core.c" "$native_module/tests/test_core.c" \
  -o "$native_check/test-core"
"$native_check/test-core"
