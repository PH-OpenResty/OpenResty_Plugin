#!/bin/sh
# Test compiler wrapper: nginx deliberately uses unaligned HTTP/2 integer
# access on supported architectures. Keep all sanitizer checks for our addons;
# disable only alignment instrumentation in the upstream HTTP/2 codecs.
set -eu
scdn_http2_source=0
for scdn_cc_arg in "$@"; do
    case "$scdn_cc_arg" in
        src/http/v2/*.c|*/src/http/v2/*.c|\
        src/http/modules/ngx_http_grpc_module.c|*/src/http/modules/ngx_http_grpc_module.c|\
        src/http/modules/ngx_http_proxy_v2_module.c|*/src/http/modules/ngx_http_proxy_v2_module.c)
            scdn_http2_source=1;;
    esac
done
if [ "$scdn_http2_source" = 1 ]; then
    exec "${SCDN_NATIVE_REAL_CC:-cc}" "$@" -fno-sanitize=alignment
fi
exec "${SCDN_NATIVE_REAL_CC:-cc}" "$@"
