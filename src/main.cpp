#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>

struct EVP_MD_CTX_Deleter {
  void operator()(EVP_MD_CTX* ctx) const {
    if (ctx) {
      EVP_MD_CTX_free(ctx);
    }
  }
};

std::string sha256_of_file(const std::string& file_path) {
  std::ifstream file{file_path, std::ios::binary};
  if (!file) {
    throw std::runtime_error{"Failed to open file: " + file_path};
  }
  std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx{EVP_MD_CTX_new()};
  if (!ctx) {
    throw std::runtime_error{"Failed to create EVP_MD_CTX"};
  }
  if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
    throw std::runtime_error{"Failed to initialize EVP_MD_CTX"};
  }
  std::array<char, 8192> buffer;
  while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
    if (EVP_DigestUpdate(ctx.get(), buffer.data(), file.gcount()) != 1) {
      throw std::runtime_error{"Failed to update EVP_MD_CTX"};
    }
  }
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_length;
  if (EVP_DigestFinal_ex(ctx.get(), hash, &hash_length) != 1) {
    throw std::runtime_error{"Failed to finalize EVP_MD_CTX"};
  }
  std::stringstream hex_hash;
  for (const auto& byte : std::span(hash, hash_length)) {
    hex_hash << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
  }
  return hex_hash.str();
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " [...file paths]" << std::endl;
    return 1;
  }

  auto start = std::chrono::high_resolution_clock::now();
  for (int i{1}; i < argc; ++i) {
    try {
      std::cout << sha256_of_file(argv[i]) << "  " << argv[i] << std::endl;
    } catch (const std::exception& e) {
      std::cerr << "Error: " << e.what() << std::endl;
    }
  }

  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed_seconds = end - start;
  std::cout << "Elapsed time: " << elapsed_seconds.count() << "s" << std::endl;
  return 0;
}
