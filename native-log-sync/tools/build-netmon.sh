#!/bin/sh
set -eu
log_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
log_output=${1:?provide an absolute output directory}
case "$log_output" in /*) ;; *) exit 1;; esac
mkdir -p "$log_output"
log_arch=$(cc -dumpmachine)
clang -target bpf -O2 -g -Wall -Werror -I /usr/include -I "/usr/include/$log_arch" \
    -c "$log_root/bpf/packet.bpf.c" -o "$log_output/packet.bpf.o"
${CXX:-c++} -std=c++17 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation -pthread \
    $(pkg-config --cflags json-c libcurl libbpf openssl zlib) -I "$log_root/src" \
    "$log_root/src/log_sync_netmon.cpp" "$log_output/libscdn-log-sync.a" \
    $(pkg-config --libs json-c libcurl libbpf openssl zlib) -o "$log_output/scdn-log-netmon"
${CXX:-c++} -std=c++17 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation \
    "$log_root/tests/packets.cpp" $(pkg-config --cflags --libs libbpf) -o "$log_output/packet-tests"
