#!/bin/sh
set -eu
ban_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ban_output=${1:?provide an absolute isolated build directory}
case "$ban_output" in /*) ;; *) exit 1;; esac
mkdir -p "$ban_output"
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror ${BAN_SANITIZERS:-} -I "$ban_root/src" -c "$ban_root/src/ban_common.c" -o "$ban_output/ban_common.o"
${CXX:-c++} -std=c++17 -O2 -g -Wall -Wextra -Werror -pthread ${BAN_SANITIZERS:-} \
  $(pkg-config --cflags libbpf json-c sqlite3 libcurl openssl) -I "$ban_root/src" -I "$ban_root/agent" \
  "$ban_root/agent/main.cpp" "$ban_root/agent/util.cpp" "$ban_root/agent/config.cpp" \
  "$ban_root/agent/kernel.cpp" "$ban_root/agent/engine.cpp" "$ban_root/agent/cluster.cpp" "$ban_root/agent/server.cpp" \
  "$ban_output/ban_common.o" $(pkg-config --libs libbpf json-c sqlite3 libcurl openssl) -o "$ban_output/scdn-ban-agent"
ban_arch_include=$(cc -dumpmachine)
clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Werror \
  -I /usr/include -I "/usr/include/$ban_arch_include" -c "$ban_root/bpf/ban.bpf.c" -o "$ban_output/ban.bpf.o"
