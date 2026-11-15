#!/bin/sh
# Compatibility entry point; keep all five modules on the unified build path.
set -eu
native_module=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec sh "$native_module/../tools/build-runtime.sh" "$@"
