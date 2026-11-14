#!/bin/sh
# Build either the nginx core alone or the complete pinned OpenResty bundle.
set -eu
native_prefix=${1:?provide an absolute isolated prefix}
native_runtime=${2:-nginx}
case "$native_prefix" in /*) ;; *) echo 'prefix must be absolute' >&2; exit 1;; esac
if [ -e "$native_prefix/sbin/nginx" ] || [ -e "$native_prefix/nginx/sbin/nginx" ]; then
    echo 'refusing to overwrite an existing nginx installation' >&2
    exit 1
fi
native_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
native_work=$(mktemp -d /tmp/scdn-native-build.XXXXXXXX)
trap 'rm -rf -- "$native_work"' EXIT
trap 'exit 1' HUP INT TERM
native_archive="$native_work/openresty.tar.gz"
native_sha=b569c63b420f80a4ac8466f2deffe73ed93ab760026532e039c3658409a997f4
curl --proto '=https' --tlsv1.2 -fsS \
  https://openresty.org/download/openresty-1.31.8.1.tar.gz -o "$native_archive"
printf '%s  %s\n' "$native_sha" "$native_archive" | sha256sum -c > /dev/null
case "$native_runtime" in
  nginx)
    tar -xzf "$native_archive" -C "$native_work" \
      openresty-1.31.8.1/bundle/nginx-1.31.8
    cd "$native_work/openresty-1.31.8.1/bundle/nginx-1.31.8"
    ;;
  openresty)
    tar -xzf "$native_archive" -C "$native_work"
    cd "$native_work/openresty-1.31.8.1"
    ;;
  *) echo 'runtime must be nginx or openresty' >&2; exit 1;;
esac
./configure --prefix="$native_prefix" --with-compat --with-http_ssl_module \
  --with-http_v2_module --with-pcre-jit --with-threads \
  --with-cc-opt="${SCDN_NATIVE_CFLAGS:--Werror}" \
  --with-ld-opt="${SCDN_NATIVE_LDFLAGS:-}" \
  --add-dynamic-module="$native_root/native-config" \
  --add-dynamic-module="$native_root/native-edge" \
  --add-dynamic-module="$native_root/native-purge"
make -j"${SCDN_NATIVE_BUILD_JOBS:-2}"
make install
