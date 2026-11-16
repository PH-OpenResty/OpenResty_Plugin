// Offline fault fixture for signed-snapshot replay tests, never an Agent RPC.
#include "ban_store.hpp"
#include <iostream>
#include <iterator>
#include <stdexcept>
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      return 2;
    ban_store::Options options;
    options.directory = argv[1];
    ban_store::Store store(options);
    std::string value{std::istreambuf_iterator<char>(std::cin), {}};
    if (value.empty() || value.size() > 4u * 1024u * 1024u)
      throw std::runtime_error("fixture_snapshot_size");
    store.put(ban_store::Table::Meta, "snapshot", value);
  } catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
