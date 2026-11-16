#!/bin/sh
set -eu
store_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
store_output=${1:?provide an absolute isolated build directory}
case "$store_output" in /*) ;; *) exit 1;; esac
mkdir -p "$store_output"
${CXX:-c++} -std=c++17 -O2 -g -Wall -Wextra -Werror ${BAN_SANITIZERS:-} \
  -I "$store_root/include" -c "$store_root/src/ban_store.cpp" -o "$store_output/ban_store.o"
ar rcs "$store_output/libscdn-ban-store.a" "$store_output/ban_store.o"
${CXX:-c++} -std=c++17 -O2 -g -Wall -Wextra -Werror ${BAN_SANITIZERS:-} \
  -I "$store_root/include" "$store_root/tests/store_test.cpp" \
  "$store_output/libscdn-ban-store.a" -lcrypto -o "$store_output/store-test"
${CXX:-c++} -std=c++17 -O2 -g -Wall -Wextra -Werror ${BAN_SANITIZERS:-} \
  -I "$store_root/include" "$store_root/tests/io_test.cpp" "$store_output/libscdn-ban-store.a" \
  -Wl,--wrap=write,--wrap=fdatasync,--wrap=fsync,--wrap=renameat -lcrypto -o "$store_output/io-test"
${CXX:-c++} -std=c++17 -O2 -g -Wall -Wextra -Werror ${BAN_SANITIZERS:-} \
  -I "$store_root/include" "$store_root/bench/store_bench.cpp" \
  "$store_output/libscdn-ban-store.a" -lcrypto -o "$store_output/store-bench"
