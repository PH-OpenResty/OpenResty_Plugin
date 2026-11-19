#!/bin/sh
set -eu
log_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
log_output=${1:?provide an absolute build directory}
case "$log_output" in /*) ;; *) exit 1;; esac
mkdir -p "$log_output"
log_objects=
for log_name in util http engine telemetry normalize service; do
    ${CXX:-c++} -std=c++17 -O2 -g -fPIC -pthread -Wall -Wextra -Werror ${LOG_SYNC_CFLAGS:-} \
        $(pkg-config --cflags json-c libcurl openssl libbpf zlib) -I "$log_root/src" \
        -c "$log_root/src/log_sync_$log_name.cpp" -o "$log_output/log_sync_$log_name.o"
    log_objects="$log_objects $log_output/log_sync_$log_name.o"
done
ar rcs "$log_output/libscdn-log-sync.a" $log_objects
${CXX:-c++} -std=c++17 -O2 -g -pthread ${LOG_SYNC_CFLAGS:-} -I "$log_root/src" \
    $(pkg-config --cflags json-c libcurl openssl libbpf zlib) "$log_root/src/log_sync_main.cpp" \
    "$log_output/libscdn-log-sync.a" $(pkg-config --libs json-c libcurl openssl libbpf zlib) -o "$log_output/scdn-log-sync"
